use std::{
    collections::HashMap,
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Frame, Incoming},
    server::conn::http1,
};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    process::Command,
    sync::Mutex,
    time::{interval, timeout},
};
use tracing::{error, info, warn};

const MAX_REQUEST_BYTES: usize = 8 * 1024;
const MAX_REFERENCE_BYTES: usize = 2 * 1024;
const MAX_REASON_CHARS: usize = 300;
const MAX_SECRET_BYTES: usize = 64 * 1024;
const DEFAULT_SOCKET: &str = "/run/proton-pass/broker.sock";
const DEFAULT_SESSION_DIR: &str = "/var/lib/proton-pass/session";
const DEFAULT_TOKEN_FILE: &str = "/run/secrets/proton_pass_agent_token";
const DEFAULT_PASS_CLI: &str = "/usr/local/bin/pass-cli";

#[derive(Parser)]
#[command(version, about = "Unix-socket broker for scoped Proton Pass lookups")]
struct Cli {
    #[command(subcommand)]
    command: Option<BrokerCommand>,
}

#[derive(Subcommand)]
enum BrokerCommand {
    Serve,
    Healthcheck,
}

#[derive(Clone)]
struct Config {
    socket: PathBuf,
    session_dir: PathBuf,
    token_file: PathBuf,
    pass_cli: PathBuf,
    command_timeout: Duration,
    session_check_interval: Duration,
}

impl Config {
    fn from_env() -> Result<Self> {
        Ok(Self {
            socket: env_path("PROTON_PASS_SOCKET", DEFAULT_SOCKET),
            session_dir: env_path("PROTON_PASS_SESSION_DIR", DEFAULT_SESSION_DIR),
            token_file: env_path("PROTON_PASS_TOKEN_FILE", DEFAULT_TOKEN_FILE),
            pass_cli: env_path("PROTON_PASS_CLI", DEFAULT_PASS_CLI),
            command_timeout: Duration::from_secs(env_u64(
                "PROTON_PASS_COMMAND_TIMEOUT_SECONDS",
                60,
            )?),
            session_check_interval: Duration::from_secs(env_u64(
                "PROTON_PASS_SESSION_CHECK_SECONDS",
                300,
            )?),
        })
    }
}

fn env_path(name: &str, default: &str) -> PathBuf {
    env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default))
}

fn env_u64(name: &str, default: u64) -> Result<u64> {
    match env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .with_context(|| format!("{name} must be a positive integer")),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error.into()),
    }
}

struct AuthManager {
    config: Config,
    command_gate: Mutex<()>,
    healthy: AtomicBool,
}

impl AuthManager {
    fn new(config: Config) -> Self {
        Self {
            config,
            command_gate: Mutex::new(()),
            healthy: AtomicBool::new(false),
        }
    }

    fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    async fn ensure_authenticated(&self) -> Result<()> {
        let _guard = self.command_gate.lock().await;
        self.ensure_authenticated_locked().await
    }

    async fn ensure_authenticated_locked(&self) -> Result<()> {
        if self.run_pass_cli(&["test"], HashMap::new()).await.is_ok() {
            self.healthy.store(true, Ordering::Relaxed);
            return Ok(());
        }

        self.healthy.store(false, Ordering::Relaxed);
        let token = read_token(&self.config.token_file)?;
        let mut environment = HashMap::new();
        environment.insert("PROTON_PASS_PERSONAL_ACCESS_TOKEN".to_string(), token);

        self.run_pass_cli(&["login"], environment)
            .await
            .context("Proton Pass login failed")?;
        self.run_pass_cli(&["test"], HashMap::new())
            .await
            .context("Proton Pass session validation failed after login")?;
        self.healthy.store(true, Ordering::Relaxed);
        Ok(())
    }

    async fn resolve(&self, reference: &str, reason: &str) -> Result<String> {
        validate_reference(reference)?;
        validate_reason(reason)?;

        let _guard = self.command_gate.lock().await;
        if !self.is_healthy() {
            self.ensure_authenticated_locked().await?;
        }

        match self.resolve_locked(reference, reason).await {
            Ok(secret) => {
                self.healthy.store(true, Ordering::Relaxed);
                Ok(secret)
            }
            Err(first_error) => {
                self.healthy.store(false, Ordering::Relaxed);
                warn!("Secret lookup failed; validating the Proton Pass session");

                if self.run_pass_cli(&["test"], HashMap::new()).await.is_ok() {
                    self.healthy.store(true, Ordering::Relaxed);
                    return Err(first_error);
                }

                if self.ensure_authenticated_locked().await.is_err() {
                    return Err(first_error.context("Session recovery failed"));
                }

                self.resolve_locked(reference, reason)
                    .await
                    .inspect_err(|_| {
                        self.healthy.store(false, Ordering::Relaxed);
                    })
            }
        }
    }

    async fn resolve_locked(&self, reference: &str, reason: &str) -> Result<String> {
        let mut environment = HashMap::new();
        environment.insert("PROTON_PASS_AGENT_REASON".to_string(), reason.to_string());
        let output = self
            .run_pass_cli(&["item", "view", reference], environment)
            .await?;

        if output.len() > MAX_SECRET_BYTES {
            bail!("Resolved secret exceeds the configured output limit");
        }

        Ok(output.trim_end_matches(['\r', '\n']).to_string())
    }

    async fn run_pass_cli(
        &self,
        arguments: &[&str],
        extra_environment: HashMap<String, String>,
    ) -> Result<String> {
        let mut command = Command::new(&self.config.pass_cli);
        command
            .args(arguments)
            .env_clear()
            .env("HOME", "/var/lib/proton-pass")
            .env("PROTON_PASS_SESSION_DIR", &self.config.session_dir)
            .env("PROTON_PASS_KEY_PROVIDER", "fs")
            .env("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt")
            .envs(extra_environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);

        for proxy in ["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"] {
            if let Ok(value) = env::var(proxy) {
                command.env(proxy, value);
            }
        }

        let child = command.spawn().context("Unable to start pass-cli")?;
        let output = timeout(self.config.command_timeout, child.wait_with_output())
            .await
            .context("pass-cli command timed out")??;

        if !output.status.success() {
            bail!("pass-cli command failed");
        }

        String::from_utf8(output.stdout).context("pass-cli returned invalid UTF-8")
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveRequest {
    reference: String,
    reason: String,
}

#[derive(Serialize)]
struct ResolveResponse<'a> {
    value: &'a str,
}

#[derive(Serialize)]
struct ErrorResponse<'a> {
    error: &'a str,
}

type ResponseBody = Full<Bytes>;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .without_time()
        .init();

    let cli = Cli::parse();
    let config = Config::from_env()?;

    match cli.command.unwrap_or(BrokerCommand::Serve) {
        BrokerCommand::Serve => serve(config).await,
        BrokerCommand::Healthcheck => healthcheck(&config.socket).await,
    }
}

async fn serve(config: Config) -> Result<()> {
    fs::create_dir_all(&config.session_dir).context("Unable to create session directory")?;
    fs::set_permissions(&config.session_dir, fs::Permissions::from_mode(0o700))
        .context("Unable to secure session directory")?;

    let socket_parent = config
        .socket
        .parent()
        .ok_or_else(|| anyhow!("Socket path has no parent directory"))?;
    fs::create_dir_all(socket_parent).context("Unable to create socket directory")?;

    if config.socket.exists() {
        fs::remove_file(&config.socket).context("Unable to remove stale broker socket")?;
    }

    let listener = UnixListener::bind(&config.socket).context("Unable to bind broker socket")?;
    fs::set_permissions(&config.socket, fs::Permissions::from_mode(0o660))
        .context("Unable to set broker socket permissions")?;

    let manager = Arc::new(AuthManager::new(config.clone()));
    if let Err(error) = manager.ensure_authenticated().await {
        warn!(error = %error, "Initial Proton Pass authentication failed");
    }

    let periodic_manager = Arc::clone(&manager);
    let check_interval = config.session_check_interval;
    tokio::spawn(async move {
        let mut ticker = interval(check_interval);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if let Err(error) = periodic_manager.ensure_authenticated().await {
                warn!(error = %error, "Periodic Proton Pass session check failed");
            }
        }
    });

    info!(socket = %config.socket.display(), "Proton Pass broker is listening");

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("Unable to accept broker connection")?;
                let request_manager = Arc::clone(&manager);
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(move |request| {
                        handle_request(request, Arc::clone(&request_manager))
                    });

                    if let Err(error) = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await
                    {
                        warn!(error = %error, "Broker connection failed");
                    }
                });
            }
            signal = tokio::signal::ctrl_c() => {
                signal.context("Unable to listen for shutdown signal")?;
                info!("Shutting down Proton Pass broker");
                break;
            }
        }
    }

    let _ = fs::remove_file(&config.socket);
    Ok(())
}

async fn handle_request(
    request: Request<Incoming>,
    manager: Arc<AuthManager>,
) -> Result<Response<ResponseBody>, std::convert::Infallible> {
    let response = match (request.method(), request.uri().path()) {
        (&Method::GET, "/healthz") => {
            if manager.is_healthy() {
                json_response(StatusCode::OK, serde_json::json!({"status": "ok"}))
            } else {
                json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    serde_json::json!({"status": "unhealthy"}),
                )
            }
        }
        (&Method::POST, "/v1/resolve") => match read_limited_body(request.into_body()).await {
            Ok(body) => match serde_json::from_slice::<ResolveRequest>(&body) {
                Ok(payload) => match manager.resolve(&payload.reference, &payload.reason).await {
                    Ok(value) => match serde_json::to_value(ResolveResponse { value: &value }) {
                        Ok(json) => json_response(StatusCode::OK, json),
                        Err(_) => internal_error(),
                    },
                    Err(error) => {
                        error!(error = %error, "Proton Pass secret resolution failed");
                        json_response(
                            StatusCode::BAD_GATEWAY,
                            serde_json::to_value(ErrorResponse {
                                error: "secret resolution failed",
                            })
                            .unwrap_or_default(),
                        )
                    }
                },
                Err(_) => json_response(
                    StatusCode::BAD_REQUEST,
                    serde_json::to_value(ErrorResponse {
                        error: "invalid request",
                    })
                    .unwrap_or_default(),
                ),
            },
            Err(status) => json_response(
                status,
                serde_json::to_value(ErrorResponse {
                    error: "invalid request",
                })
                .unwrap_or_default(),
            ),
        },
        _ => json_response(
            StatusCode::NOT_FOUND,
            serde_json::to_value(ErrorResponse { error: "not found" }).unwrap_or_default(),
        ),
    };

    Ok(response)
}

async fn read_limited_body(mut body: Incoming) -> std::result::Result<Vec<u8>, StatusCode> {
    let mut collected = Vec::new();

    while let Some(frame) = body.frame().await {
        let frame: Frame<Bytes> = frame.map_err(|_| StatusCode::BAD_REQUEST)?;
        if let Ok(data) = frame.into_data() {
            if collected.len() + data.len() > MAX_REQUEST_BYTES {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            collected.extend_from_slice(&data);
        }
    }

    Ok(collected)
}

fn json_response(status: StatusCode, value: serde_json::Value) -> Response<ResponseBody> {
    let body =
        serde_json::to_vec(&value).unwrap_or_else(|_| b"{\"error\":\"internal error\"}".to_vec());
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| internal_error())
}

fn internal_error() -> Response<ResponseBody> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(Full::new(Bytes::from_static(
            b"{\"error\":\"internal error\"}",
        )))
        .expect("static response must be valid")
}

fn validate_reference(reference: &str) -> Result<()> {
    if reference.len() > MAX_REFERENCE_BYTES {
        bail!("Secret reference is too long");
    }
    if !reference.is_ascii() || reference.chars().any(char::is_whitespace) {
        bail!("Secret reference must be ASCII without whitespace");
    }

    let remainder = reference
        .strip_prefix("pass://")
        .ok_or_else(|| anyhow!("Secret reference must start with pass://"))?;
    let mut components = remainder.splitn(3, '/');
    let share_id = components.next().unwrap_or_default();
    let item_id = components.next().unwrap_or_default();
    let field = components.next().unwrap_or_default();

    if share_id.is_empty() || item_id.is_empty() || field.is_empty() {
        bail!("Secret reference must contain share ID, item ID, and field");
    }
    if field.ends_with('/') {
        bail!("Secret reference must not end with a slash");
    }
    Ok(())
}

fn validate_reason(reason: &str) -> Result<()> {
    if reason.trim().is_empty() {
        bail!("Audit reason must not be empty");
    }
    if reason.chars().count() > MAX_REASON_CHARS {
        bail!("Audit reason is too long");
    }
    Ok(())
}

fn read_token(path: &Path) -> Result<String> {
    let metadata = fs::metadata(path).context("Unable to inspect Proton Pass token file")?;
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!("Proton Pass token file must not be accessible by group or others");
    }

    let token = fs::read_to_string(path)
        .context("Unable to read Proton Pass token file")?
        .trim()
        .to_string();
    if !token.starts_with("pst_") || !token.contains("::") {
        bail!("Proton Pass token file has an invalid format");
    }
    Ok(token)
}

async fn healthcheck(socket: &Path) -> Result<()> {
    let mut stream = timeout(Duration::from_secs(5), UnixStream::connect(socket))
        .await
        .context("Broker healthcheck connection timed out")??;
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .context("Unable to send healthcheck request")?;

    let mut response = Vec::with_capacity(512);
    timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .context("Broker healthcheck response timed out")??;

    if response.starts_with(b"HTTP/1.1 200") {
        Ok(())
    } else {
        bail!("Broker is unhealthy")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicU64, Ordering},
    };

    #[test]
    fn accepts_valid_reference() {
        assert!(validate_reference("pass://share_123/item_456/password").is_ok());
    }

    #[test]
    fn rejects_reference_without_field() {
        assert!(validate_reference("pass://share_123/item_456").is_err());
    }

    #[test]
    fn rejects_invalid_reference_scheme() {
        assert!(validate_reference("https://share/item/password").is_err());
    }

    #[test]
    fn rejects_reference_with_whitespace() {
        assert!(validate_reference("pass://share id/item/password").is_err());
    }

    #[test]
    fn validates_audit_reason() {
        assert!(validate_reason("Semaphore deploy karakeep").is_ok());
        assert!(validate_reason(" ").is_err());
        assert!(validate_reason(&"x".repeat(301)).is_err());
    }

    #[test]
    fn token_file_must_be_private() {
        let directory = tempfile::tempdir().expect("temp directory");
        let token_path = directory.path().join("token");
        fs::write(&token_path, "pst_example::key\n").expect("write token");

        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o644))
            .expect("set permissions");
        assert!(read_token(&token_path).is_err());

        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o400))
            .expect("set permissions");
        assert_eq!(read_token(&token_path).unwrap(), "pst_example::key");
    }

    #[tokio::test]
    async fn broker_resolves_secret_without_logging_the_value() {
        let test = BrokerTest::new();
        let manager = Arc::new(AuthManager::new(test.config()));
        manager.ensure_authenticated().await.unwrap();

        let secret = manager
            .resolve(
                "pass://share_123/item_456/password",
                "Semaphore deploy karakeep",
            )
            .await
            .unwrap();
        assert_eq!(secret, "super-secret");

        let log = fs::read_to_string(&test.log_path).unwrap();
        assert!(log.contains("item view pass://share_123/item_456/password"));
        assert!(log.contains("reason=Semaphore deploy karakeep"));
        assert!(!log.contains("super-secret"));
    }

    #[tokio::test]
    async fn broker_logs_in_from_token_when_session_is_missing() {
        let test = BrokerTest::new();
        fs::write(&test.state_path, "logged-out").unwrap();

        let manager = AuthManager::new(test.config());
        manager.ensure_authenticated().await.unwrap();

        let log = fs::read_to_string(&test.log_path).unwrap();
        assert!(log.contains("login token=pst_example::key"));
        assert!(manager.is_healthy());
    }

    struct BrokerTest {
        _directory: tempfile::TempDir,
        pass_cli_path: PathBuf,
        token_path: PathBuf,
        session_path: PathBuf,
        state_path: PathBuf,
        log_path: PathBuf,
    }

    impl BrokerTest {
        fn new() -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let directory = tempfile::tempdir().unwrap();
            let pass_cli_path = directory.path().join("pass-cli");
            let token_path = directory.path().join("token");
            let session_path = directory.path().join("session");
            let state_path = directory.path().join("state");
            let log_path = directory.path().join(format!(
                "commands-{}.log",
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));

            fs::create_dir(&session_path).unwrap();
            fs::write(&token_path, "pst_example::key\n").unwrap();
            fs::set_permissions(&token_path, fs::Permissions::from_mode(0o400)).unwrap();
            fs::write(&state_path, "logged-in").unwrap();

            let script = format!(
                r#"#!/bin/sh
set -eu
state="{}"
log="{}"
case "$1" in
  test)
    test "$(cat "$state")" = "logged-in"
    ;;
  login)
    printf 'login token=%s\n' "$PROTON_PASS_PERSONAL_ACCESS_TOKEN" >> "$log"
    printf 'logged-in' > "$state"
    ;;
  item)
    printf 'item view %s reason=%s\n' "$3" "$PROTON_PASS_AGENT_REASON" >> "$log"
    printf 'super-secret\n'
    ;;
  *)
    exit 1
    ;;
esac
"#,
                state_path.display(),
                log_path.display()
            );
            fs::write(&pass_cli_path, script).unwrap();
            fs::set_permissions(&pass_cli_path, fs::Permissions::from_mode(0o700)).unwrap();

            Self {
                _directory: directory,
                pass_cli_path,
                token_path,
                session_path,
                state_path,
                log_path,
            }
        }

        fn config(&self) -> Config {
            Config {
                socket: self.session_path.join("broker.sock"),
                session_dir: self.session_path.clone(),
                token_file: self.token_path.clone(),
                pass_cli: self.pass_cli_path.clone(),
                command_timeout: Duration::from_secs(2),
                session_check_interval: Duration::from_secs(300),
            }
        }
    }
}
