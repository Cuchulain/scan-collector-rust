use askama::Template;
use axum::{
    Router,
    body::Body,
    extract::{Form, Path, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use chrono::{Local, NaiveDate};
use rand::{RngCore, rngs::OsRng};
use rusqlite::{Connection, params};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    env, fs, io,
    path::{Path as FsPath, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex as AsyncMutex;

const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const SESSION_COOKIE: &str = "scan_collector_session";
const CSV_HEADER: [&str; 4] = ["čas", "obsah", "formát", "zařízení"];
type SharedState = Arc<AppState>;

struct AppState {
    data_dir: PathBuf,
    username: String,
    password: String,
    session_ttl: Duration,
    extended_ttl: Duration,
    secure_cookie: bool,
    db: AsyncMutex<Connection>,
    csv_lock: Arc<Mutex<()>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    timestamp: String,
    content: String,
    format: String,
    device_id: String,
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    extended: Option<String>,
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    sets: Vec<CsvSet>,
}

#[derive(Template)]
#[template(path = "detail.html")]
struct DetailTemplate {
    date: String,
    entries: Vec<EntryView>,
    total: usize,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    error: bool,
}

struct CsvSet {
    date: String,
    count: usize,
}
struct EntryView {
    timestamp: String,
    content: String,
    format: String,
    device: String,
}

impl AppState {
    fn new(
        data_dir: PathBuf,
        username: String,
        password: String,
        session_ttl: Duration,
        extended_ttl: Duration,
        secure_cookie: bool,
    ) -> io::Result<SharedState> {
        fs::create_dir_all(&data_dir)?;
        let db = Connection::open(data_dir.join("sessions.sqlite3")).map_err(io::Error::other)?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS sessions (
                 token_hash TEXT PRIMARY KEY NOT NULL,
                 expires_at INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);",
        )
        .map_err(io::Error::other)?;
        Ok(Arc::new(Self {
            data_dir,
            username,
            password,
            session_ttl,
            extended_ttl,
            secure_cookie,
            db: AsyncMutex::new(db),
            csv_lock: Arc::new(Mutex::new(())),
        }))
    }
}

fn app(state: SharedState) -> Router {
    Router::new()
        .route("/", get(index).post(submit))
        .route("/sets/{file}", get(set_file))
        .route("/login", get(login_page).post(login))
        .route("/logout", post(logout))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_session,
        ))
        .with_state(state)
}

async fn require_session(
    State(state): State<SharedState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if path == "/login" || (path == "/" && request.method() == axum::http::Method::POST) {
        return next.run(request).await;
    }
    if has_session(&state, request.headers()).await {
        next.run(request).await
    } else {
        Redirect::to("/login").into_response()
    }
}

fn cookie_value(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| {
            let (name, value) = part.trim().split_once('=')?;
            (name == SESSION_COOKIE).then(|| value.to_owned())
        })
}

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

async fn has_session(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(token) = cookie_value(headers) else {
        return false;
    };
    let db = state.db.lock().await;
    let now = chrono::Utc::now().timestamp();
    db.query_row(
        "SELECT expires_at FROM sessions WHERE token_hash = ?1",
        [token_hash(&token)],
        |row| row.get::<_, i64>(0),
    )
    .map(|expires| expires > now)
    .unwrap_or(false)
}

fn cookie_header(state: &AppState, value: &str, max_age: i64) -> HeaderValue {
    let secure = if state.secure_cookie { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}"
    ))
    .expect("cookie header is valid")
}

fn render_login(error: bool, status: StatusCode) -> Response {
    match (LoginTemplate { error }).render() {
        Ok(page) => (status, Html(page)).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn login_page() -> Response {
    render_login(false, StatusCode::OK)
}

async fn login(State(state): State<SharedState>, Form(form): Form<LoginForm>) -> Response {
    let supplied_user = Sha256::digest(form.username.as_bytes());
    let expected_user = Sha256::digest(state.username.as_bytes());
    let supplied_password = Sha256::digest(form.password.as_bytes());
    let expected_password = Sha256::digest(state.password.as_bytes());
    let user_ok = supplied_user
        .as_slice()
        .ct_eq(expected_user.as_slice())
        .unwrap_u8()
        == 1;
    let pass_ok = supplied_password
        .as_slice()
        .ct_eq(expected_password.as_slice())
        .unwrap_u8()
        == 1;
    if !user_ok || !pass_ok {
        return render_login(true, StatusCode::UNAUTHORIZED);
    }

    let ttl = if form.extended.is_some() {
        state.extended_ttl
    } else {
        state.session_ttl
    };
    let expires = chrono::Utc::now()
        .timestamp()
        .saturating_add(ttl.as_secs().min(i64::MAX as u64) as i64);
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let token = hex::encode(bytes);
    let db = state.db.lock().await;
    let result = (|| -> io::Result<()> {
        db.execute(
            "DELETE FROM sessions WHERE expires_at <= ?1",
            [chrono::Utc::now().timestamp()],
        )
        .map_err(io::Error::other)?;
        db.execute(
            "INSERT INTO sessions(token_hash, expires_at) VALUES (?1, ?2)",
            params![token_hash(&token), expires],
        )
        .map_err(io::Error::other)?;
        Ok(())
    })();
    if result.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let mut response = Redirect::to("/").into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        cookie_header(&state, &token, ttl.as_secs() as i64),
    );
    response
}

async fn logout(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if let Some(token) = cookie_value(&headers) {
        let db = state.db.lock().await;
        let _ = db.execute(
            "DELETE FROM sessions WHERE token_hash = ?1",
            [token_hash(&token)],
        );
    }
    let mut response = Redirect::to("/login").into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, cookie_header(&state, "", 0));
    response
}

async fn index(State(state): State<SharedState>) -> Response {
    let data_dir = state.data_dir.clone();
    let result = tokio::task::spawn_blocking(move || list_sets(&data_dir)).await;
    match result {
        Ok(Ok(sets)) => render(IndexTemplate { sets }),
        _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn render<T: Template>(template: T) -> Response {
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn list_sets(dir: &FsPath) -> io::Result<Vec<CsvSet>> {
    let mut sets = Vec::new();
    for item in fs::read_dir(dir)? {
        let item = item?;
        let name = item.file_name().to_string_lossy().into_owned();
        let Some(date) = name
            .strip_prefix("scan-")
            .and_then(|n| n.strip_suffix(".csv"))
        else {
            continue;
        };
        if item.file_type()?.is_dir() || NaiveDate::parse_from_str(date, "%Y-%m-%d").is_err() {
            continue;
        }
        let mut reader = csv::Reader::from_path(item.path()).map_err(io::Error::other)?;
        let count = reader.records().count();
        sets.push(CsvSet {
            date: date.to_owned(),
            count,
        });
    }
    sets.sort_by(|a, b| b.date.cmp(&a.date));
    Ok(sets)
}

async fn set_file(State(state): State<SharedState>, Path(file): Path<String>) -> Response {
    if let Some(date) = file.strip_suffix(".csv") {
        return download_date(state, date.to_owned()).await;
    }
    detail_date(state, file).await
}

async fn detail_date(state: SharedState, date: String) -> Response {
    if NaiveDate::parse_from_str(&date, "%Y-%m-%d").is_err() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let path = state.data_dir.join(format!("scan-{date}.csv"));
    let result = tokio::task::spawn_blocking(move || read_entries(path)).await;
    match result {
        Ok(Ok(entries)) => render(DetailTemplate {
            date,
            total: entries.len(),
            entries,
        }),
        Ok(Err(err)) if err.kind() == io::ErrorKind::NotFound => {
            StatusCode::NOT_FOUND.into_response()
        }
        _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn read_entries(path: PathBuf) -> io::Result<Vec<EntryView>> {
    let mut reader = csv::Reader::from_path(path).map_err(io::Error::other)?;
    reader
        .records()
        .map(|row| {
            let row = row.map_err(io::Error::other)?;
            Ok(EntryView {
                timestamp: row.get(0).unwrap_or_default().to_owned(),
                content: row.get(1).unwrap_or_default().to_owned(),
                format: row.get(2).unwrap_or_default().to_owned(),
                device: row.get(3).unwrap_or_default().to_owned(),
            })
        })
        .collect()
}

async fn download_date(state: SharedState, date: String) -> Response {
    if NaiveDate::parse_from_str(&date, "%Y-%m-%d").is_err() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let path = state.data_dir.join(format!("scan-{date}.csv"));
    match tokio::fs::read(path).await {
        Ok(bytes) => {
            let mut response = (
                [(header::CONTENT_TYPE, "text/csv; charset=utf-8")],
                Body::from(bytes),
            )
                .into_response();
            response.headers_mut().insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&format!("attachment; filename=scan-{date}.csv")).unwrap(),
            );
            response
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn submit(State(state): State<SharedState>, body: axum::body::Bytes) -> Response {
    if body.len() > MAX_REQUEST_BYTES {
        return (StatusCode::BAD_REQUEST, "invalid JSON body").into_response();
    }
    let entry: Entry = match serde_json::from_slice(&body) {
        Ok(entry) => entry,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid JSON body").into_response(),
    };
    let data_dir = state.data_dir.clone();
    let lock = state.csv_lock.clone();
    let result = tokio::task::spawn_blocking(move || append_entry(&data_dir, &lock, entry)).await;
    match result {
        Ok(Ok(())) => (StatusCode::OK, "OK").into_response(),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "could not save entry").into_response(),
    }
}

fn append_entry(dir: &FsPath, lock: &Mutex<()>, entry: Entry) -> io::Result<()> {
    let _guard = lock
        .lock()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "CSV lock was poisoned"))?;
    fs::create_dir_all(dir)?;
    let date = Local::now().format("%Y-%m-%d").to_string();
    let path = dir.join(format!("scan-{date}.csv"));
    let new_file = !path.exists() || fs::metadata(&path)?.len() == 0;
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let mut writer = csv::Writer::from_writer(file);
    if new_file {
        writer.write_record(CSV_HEADER).map_err(io::Error::other)?;
    }
    writer
        .write_record([
            entry.timestamp,
            entry.content,
            entry.format,
            entry.device_id,
        ])
        .map_err(io::Error::other)?;
    writer.flush().map_err(io::Error::other)
}

fn parse_duration_env(key: &str, default: &str) -> Result<Duration, String> {
    let value = env::var(key).unwrap_or_else(|_| default.to_owned());
    let duration =
        humantime::parse_duration(&value).map_err(|err| format!("invalid {key}: {err}"))?;
    if duration.is_zero() {
        return Err(format!("{key} must be greater than zero"));
    }
    Ok(duration)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let username = env::var("AUTH_USER").map_err(|_| "AUTH_USER must be configured")?;
    let password = env::var("AUTH_PASSWORD").map_err(|_| "AUTH_PASSWORD must be configured")?;
    let port = env::var("PORT")
        .unwrap_or_else(|_| "8765".to_owned())
        .trim_start_matches(':')
        .parse::<u16>()?;
    let data_dir = PathBuf::from(env::var("DATA_DIR").unwrap_or_else(|_| "/data".to_owned()));
    let session_ttl = parse_duration_env("SESSION_TTL", "8h")?;
    let extended_ttl = parse_duration_env("SESSION_EXTENDED_TTL", "720h")?;
    let secure_cookie = env::var("COOKIE_SECURE")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let state = AppState::new(
        data_dir.clone(),
        username,
        password,
        session_ttl,
        extended_ttl,
        secure_cookie,
    )?;
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    eprintln!(
        "Listening on 0.0.0.0:{port}; data in {}",
        data_dir.display()
    );
    axum::serve(listener, app(state)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn test_state() -> (SharedState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let state = AppState::new(
            dir.path().to_owned(),
            "admin".into(),
            "secret".into(),
            Duration::from_secs(2),
            Duration::from_secs(3600),
            false,
        )
        .unwrap();
        (state, dir)
    }

    #[tokio::test]
    async fn scan_post_is_public_and_writes_daily_csv() {
        let (state, dir) = test_state();
        let response = app(state).oneshot(Request::post("/").header(header::CONTENT_TYPE, "application/json").body(Body::from(r#"{"timestamp":"2026-09-25T12:00:00Z","content":"CODE-12345","format":"QR_CODE","deviceId":"scanner-1"}"#)).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let path = dir
            .path()
            .join(format!("scan-{}.csv", Local::now().format("%Y-%m-%d")));
        let rows = csv::Reader::from_path(path)
            .unwrap()
            .records()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get(1), Some("CODE-12345"));
    }

    #[tokio::test]
    async fn invalid_json_is_rejected() {
        let (state, _) = test_state();
        let response = app(state)
            .oneshot(Request::post("/").body(Body::from("{")).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn login_session_protects_pages_and_persists_in_database() {
        let (state, dir) = test_state();
        let response = app(state.clone())
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let body = "username=admin&password=secret&extended=on";
        let response = app(state.clone())
            .oneshot(
                Request::post("/login")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        assert!(
            response
                .headers()
                .get(header::SET_COOKIE)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("Max-Age=3600")
        );
        let response = app(state)
            .oneshot(
                Request::get("/")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let data = response.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&data).contains("Scan Collector"));
        let state_after_restart = AppState::new(
            dir.path().to_owned(),
            "admin".into(),
            "secret".into(),
            Duration::from_secs(2),
            Duration::from_secs(3600),
            false,
        )
        .unwrap();
        let response = app(state_after_restart)
            .oneshot(
                Request::get("/")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn wrong_password_does_not_create_session() {
        let (state, _) = test_state();
        let response = app(state)
            .oneshot(
                Request::post("/login")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("username=admin&password=wrong"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
    }

    #[tokio::test]
    async fn date_detail_and_csv_routes_match_and_require_a_session() {
        let (state, dir) = test_state();
        let date = Local::now().format("%Y-%m-%d").to_string();
        fs::write(
            dir.path().join(format!("scan-{date}.csv")),
            "čas,obsah,formát,zařízení\nnow,code,QR,scanner\n",
        )
        .unwrap();
        let cookie = create_test_session(&state).await;

        for path in [format!("/sets/{date}"), format!("/sets/{date}.csv")] {
            let response = app(state.clone())
                .oneshot(
                    Request::get(&path)
                        .header(header::COOKIE, &cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "route: {path}");
        }

        let response = app(state)
            .oneshot(
                Request::get(format!("/sets/{date}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn logout_revokes_session_and_clears_cookie() {
        let (state, _) = test_state();
        let cookie = create_test_session(&state).await;
        let response = app(state.clone())
            .oneshot(
                Request::post("/logout")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert!(
            response.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );

        let response = app(state)
            .oneshot(
                Request::get("/")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn expired_session_is_rejected() {
        let (state, _) = test_state();
        let token = "expired-token";
        state
            .db
            .lock()
            .await
            .execute(
                "INSERT INTO sessions(token_hash, expires_at) VALUES (?1, ?2)",
                params![token_hash(token), chrono::Utc::now().timestamp() - 1],
            )
            .unwrap();
        let response = app(state)
            .oneshot(
                Request::get("/")
                    .header(header::COOKIE, format!("{SESSION_COOKIE}={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }

    async fn create_test_session(state: &AppState) -> String {
        let token = "valid-test-token";
        state
            .db
            .lock()
            .await
            .execute(
                "INSERT INTO sessions(token_hash, expires_at) VALUES (?1, ?2)",
                params![token_hash(token), chrono::Utc::now().timestamp() + 3600],
            )
            .unwrap();
        format!("{SESSION_COOKIE}={token}")
    }
}
