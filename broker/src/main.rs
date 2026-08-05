use std::{
    collections::HashMap,
    env, fmt, fs,
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
const SESSION_PROBE_ARGUMENTS: &[&str] = &["info", "--output", "json"];

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

#[derive(Debug)]
struct PassCliCommandError {
    command: String,
    detail: String,
}

impl fmt::Display for PassCliCommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "pass-cli command failed: {}", self.command)
    }
}

impl std::error::Error for PassCliCommandError {}

fn is_recoverable_session_failure(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<PassCliCommandError>()
            .is_some_and(|command_error| {
                let detail = command_error.detail.to_ascii_lowercase();
                detail.contains("aead")
                    || detail.contains("local key")
                    || (detail.contains("decrypt") && detail.contains("session"))
                    || detail.contains("non-existent session")
                    || detail.contains("session has been invalidated")
                    || detail.contains("session invalidated")
            })
    })
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
        let probe_error = match self
            .run_pass_cli(SESSION_PROBE_ARGUMENTS, HashMap::new())
            .await
        {
            Ok(_) => {
                self.healthy.store(true, Ordering::Relaxed);
                return Ok(());
            }
            Err(error) => error,
        };

        self.healthy.store(false, Ordering::Relaxed);

        // Normal path: re-login from the scoped token. A connectivity failure
        // can make `info` fail while the local session remains valid; in that
        // case pass-cli answers `Already authenticated` to `login`. Preserve
        // the session unless pass-cli explicitly identifies local corruption.
        let login_error = match self.login_and_validate().await {
            Ok(()) => {
                self.healthy.store(true, Ordering::Relaxed);
                return Ok(());
            }
            Err(error) => error,
        };

        if !is_recoverable_session_failure(&probe_error)
            && !is_recoverable_session_failure(&login_error)
        {
            return Err(login_error.context(
                "Proton Pass login failed without evidence of a recoverable session failure; preserving session state",
            ));
        }

        // Recovery path: a stale or desynced local session — e.g. a local key
        // that no longer matches the encrypted session database, surfacing as
        // an AEAD decryption error — makes pass-cli fail on *every* command,
        // including login itself. Purge the local session state and retry from
        // a clean slate. The scoped token remains the source of truth, so the
        // session is always rebuildable.
        warn!("Proton Pass login failed; purging local session state and retrying");
        self.purge_session_state()?;
        self.login_and_validate()
            .await
            .context("Proton Pass login failed after purging local session state")?;
        self.healthy.store(true, Ordering::Relaxed);
        Ok(())
    }

    async fn login_and_validate(&self) -> Result<()> {
        let token = read_token(&self.config.token_file)?;
        let mut environment = HashMap::new();
        environment.insert("PROTON_PASS_PERSONAL_ACCESS_TOKEN".to_string(), token);

        self.run_pass_cli(&["login"], environment)
            .await
            .context("Proton Pass login failed")?;
        self.run_pass_cli(SESSION_PROBE_ARGUMENTS, HashMap::new())
            .await
            .context("Proton Pass session validation failed after login")?;
        Ok(())
    }

    /// Remove pass-cli's local session state (`<session_dir>/.session`, which
    /// holds the encrypted session database and the local key). Used to recover
    /// from an undecryptable session that would otherwise block every command.
    fn purge_session_state(&self) -> Result<()> {
        let state = self.config.session_dir.join(".session");
        match fs::remove_dir_all(&state) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("Unable to purge local Proton Pass session state"),
        }
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

                if self
                    .run_pass_cli(SESSION_PROBE_ARGUMENTS, HashMap::new())
                    .await
                    .is_ok()
                {
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
        let arguments = pass_cli_view_arguments(reference);
        let output = self
            .run_pass_cli(
                &arguments.iter().map(String::as_str).collect::<Vec<_>>(),
                environment,
            )
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
            .stderr(Stdio::piped())
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
            // Surface pass-cli's own diagnostics in the broker log so failures
            // (expired token, undecryptable session, network) are not opaque.
            // stderr carries error text only; the secret value, if any, is on
            // stdout and is never logged. The HTTP response stays generic.
            let stderr = String::from_utf8_lossy(&output.stderr);
            let detail = stderr.trim();
            let snippet: String = detail.chars().take(500).collect();
            warn!(
                command = arguments.first().copied().unwrap_or("?"),
                detail = if snippet.is_empty() {
                    "no stderr output"
                } else {
                    &snippet
                },
                "pass-cli command failed"
            );
            return Err(PassCliCommandError {
                command: arguments.first().copied().unwrap_or("?").to_string(),
                detail: snippet,
            }
            .into());
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

/// Reference scheme. `pass://` carries opaque, keyset-bound IDs (legacy);
/// `proton://` carries stable vault and item names resolved by pass-cli.
enum ReferenceScheme {
    Id,
    Name,
}

/// A reference split into its scheme and three `/`-separated components.
struct ParsedReference<'a> {
    scheme: ReferenceScheme,
    first: &'a str,
    second: &'a str,
    field: &'a str,
}

/// Split a `pass://` or `proton://` reference into its components without
/// validating them. Returns `None` for unknown schemes.
fn split_reference(reference: &str) -> Option<ParsedReference<'_>> {
    let (scheme, remainder) = if let Some(rest) = reference.strip_prefix("pass://") {
        (ReferenceScheme::Id, rest)
    } else if let Some(rest) = reference.strip_prefix("proton://") {
        (ReferenceScheme::Name, rest)
    } else {
        return None;
    };

    let mut components = remainder.splitn(3, '/');
    Some(ParsedReference {
        scheme,
        first: components.next().unwrap_or_default(),
        second: components.next().unwrap_or_default(),
        field: components.next().unwrap_or_default(),
    })
}

fn validate_reference(reference: &str) -> Result<()> {
    if reference.len() > MAX_REFERENCE_BYTES {
        bail!("Secret reference is too long");
    }
    if !reference.is_ascii() || reference.chars().any(char::is_whitespace) {
        bail!("Secret reference must be ASCII without whitespace");
    }

    let parsed = split_reference(reference)
        .ok_or_else(|| anyhow!("Secret reference must start with pass:// or proton://"))?;

    if parsed.first.is_empty() || parsed.second.is_empty() || parsed.field.is_empty() {
        match parsed.scheme {
            ReferenceScheme::Id => {
                bail!("Secret reference must contain share ID, item ID, and field")
            }
            ReferenceScheme::Name => {
                bail!("Secret reference must contain vault name, item title, and field")
            }
        }
    }
    if parsed.field.ends_with('/') {
        bail!("Secret reference must not end with a slash");
    }
    Ok(())
}

/// Build the `pass-cli item view` argument list for a reference. The reference
/// is assumed to have passed [`validate_reference`]. `pass://` references are
/// forwarded as a positional URI; `proton://` references are translated into
/// the named `--vault-name/--item-title/--field` flags so pass-cli resolves the
/// keyset-bound IDs at runtime.
fn pass_cli_view_arguments(reference: &str) -> Vec<String> {
    match split_reference(reference) {
        Some(ParsedReference {
            scheme: ReferenceScheme::Name,
            first,
            second,
            field,
        }) => vec![
            "item".to_string(),
            "view".to_string(),
            "--vault-name".to_string(),
            first.to_string(),
            "--item-title".to_string(),
            second.to_string(),
            "--field".to_string(),
            field.to_string(),
        ],
        _ => vec![
            "item".to_string(),
            "view".to_string(),
            reference.to_string(),
        ],
    }
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
    fn accepts_valid_name_reference() {
        assert!(validate_reference("proton://docker-secrets/traefik/CF_TUNNEL_ID").is_ok());
    }

    #[test]
    fn rejects_reference_without_field() {
        assert!(validate_reference("pass://share_123/item_456").is_err());
    }

    #[test]
    fn rejects_name_reference_without_field() {
        assert!(validate_reference("proton://docker-secrets/traefik").is_err());
    }

    #[test]
    fn rejects_invalid_reference_scheme() {
        assert!(validate_reference("https://share/item/password").is_err());
    }

    #[test]
    fn id_reference_is_forwarded_as_positional_uri() {
        assert_eq!(
            pass_cli_view_arguments("pass://share_123/item_456/password"),
            vec!["item", "view", "pass://share_123/item_456/password"]
        );
    }

    #[test]
    fn name_reference_is_translated_to_named_flags() {
        assert_eq!(
            pass_cli_view_arguments("proton://docker-secrets/traefik/CF_TUNNEL_ID"),
            vec![
                "item",
                "view",
                "--vault-name",
                "docker-secrets",
                "--item-title",
                "traefik",
                "--field",
                "CF_TUNNEL_ID",
            ]
        );
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

    #[tokio::test]
    async fn broker_recovers_from_undecryptable_session() {
        let test = BrokerTest::new_self_heal();
        let state = test.session_path.join(".session");

        let manager = AuthManager::new(test.config());
        manager.ensure_authenticated().await.unwrap();

        // The first login is blocked by the corrupt session; the broker purges
        // the local state and a retry creates a fresh, valid session.
        assert!(manager.is_healthy());
        assert!(state.join("valid").exists());
        assert!(!state.join("corrupt").exists());
    }

    #[tokio::test]
    async fn broker_preserves_valid_session_during_transient_network_failure() {
        let test = BrokerTest::new_transient_network_failure();
        let state = test.session_path.join(".session");
        let valid = state.join("valid");

        let manager = AuthManager::new(test.config());
        let error = manager.ensure_authenticated().await.unwrap_err();

        assert!(!manager.is_healthy());
        assert!(valid.exists());
        assert!(error.to_string().contains("preserving session state"));

        fs::write(&test.state_path, "network-up").unwrap();
        manager.ensure_authenticated().await.unwrap();
        assert!(manager.is_healthy());
        assert!(valid.exists());
    }

    #[tokio::test]
    async fn broker_rebuilds_explicitly_invalidated_session() {
        let test = BrokerTest::new_invalidated_session();
        let state = test.session_path.join(".session");

        let manager = AuthManager::new(test.config());
        manager.ensure_authenticated().await.unwrap();

        assert!(manager.is_healthy());
        assert!(state.join("valid").exists());
        assert!(!state.join("invalidated").exists());
    }

    #[test]
    fn purge_session_state_is_idempotent_when_absent() {
        let test = BrokerTest::new();
        let manager = AuthManager::new(test.config());
        // No .session directory exists yet; purging must succeed regardless.
        manager.purge_session_state().unwrap();
        manager.purge_session_state().unwrap();
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
  info)
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

        /// Build a harness whose mock pass-cli starts with a corrupt local
        /// session: `login` fails while `<session_dir>/.session/corrupt` exists
        /// and no `valid` marker is present, mimicking an undecryptable session
        /// that blocks every command until the state is purged.
        fn new_self_heal() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let pass_cli_path = directory.path().join("pass-cli");
            let token_path = directory.path().join("token");
            let session_path = directory.path().join("session");
            let state_path = directory.path().join("state");
            let log_path = directory.path().join("commands-self-heal.log");

            fs::create_dir(&session_path).unwrap();
            fs::write(&token_path, "pst_example::key\n").unwrap();
            fs::set_permissions(&token_path, fs::Permissions::from_mode(0o400)).unwrap();

            let state = session_path.join(".session");
            fs::create_dir_all(&state).unwrap();
            fs::write(state.join("corrupt"), "x").unwrap();

            let script = r#"#!/bin/sh
set -eu
sd="$PROTON_PASS_SESSION_DIR/.session"
case "$1" in
  info)
    test -f "$sd/valid"
    ;;
  login)
    if [ -f "$sd/corrupt" ]; then
      echo 'Error: AEAD decryption error while opening local session' >&2
      exit 1
    fi
    mkdir -p "$sd"
    : > "$sd/valid"
    ;;
  *)
    exit 1
    ;;
esac
"#;
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

        /// Build a harness with a valid persisted session while network access
        /// is temporarily unavailable. `info` reports DNS failure and `login`
        /// correctly refuses to replace the already-authenticated session.
        fn new_transient_network_failure() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let pass_cli_path = directory.path().join("pass-cli");
            let token_path = directory.path().join("token");
            let session_path = directory.path().join("session");
            let state_path = directory.path().join("network-state");
            let log_path = directory.path().join("commands-network.log");

            let state = session_path.join(".session");
            fs::create_dir_all(&state).unwrap();
            fs::write(state.join("valid"), "x").unwrap();
            fs::write(&state_path, "network-down").unwrap();
            fs::write(&token_path, "pst_example::key\n").unwrap();
            fs::set_permissions(&token_path, fs::Permissions::from_mode(0o400)).unwrap();

            let script = format!(
                r#"#!/bin/sh
set -eu
network_state="{}"
sd="$PROTON_PASS_SESSION_DIR/.session"
case "$1" in
  info)
    if [ "$(cat "$network_state")" = "network-down" ]; then
      echo 'Error: failed to connect to host: error resolving destination' >&2
      exit 1
    fi
    test -f "$sd/valid"
    ;;
  login)
    if [ -f "$sd/valid" ]; then
      echo 'Error: Already authenticated' >&2
      exit 1
    fi
    exit 1
    ;;
  *)
    exit 1
    ;;
esac
"#,
                state_path.display()
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

        /// Build a harness with local state that the service explicitly reports
        /// as invalidated. The first login sees the still-present local marker;
        /// after the broker purges it, a second login creates a valid session.
        fn new_invalidated_session() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let pass_cli_path = directory.path().join("pass-cli");
            let token_path = directory.path().join("token");
            let session_path = directory.path().join("session");
            let state_path = directory.path().join("state");
            let log_path = directory.path().join("commands-invalidated.log");

            let state = session_path.join(".session");
            fs::create_dir_all(&state).unwrap();
            fs::write(state.join("invalidated"), "x").unwrap();
            fs::write(&token_path, "pst_example::key\n").unwrap();
            fs::set_permissions(&token_path, fs::Permissions::from_mode(0o400)).unwrap();

            let script = r#"#!/bin/sh
set -eu
sd="$PROTON_PASS_SESSION_DIR/.session"
case "$1" in
  info)
    if [ -f "$sd/invalidated" ]; then
      echo 'Error: failed to authenticate: non-existent session' >&2
      exit 1
    fi
    test -f "$sd/valid"
    ;;
  login)
    if [ -f "$sd/invalidated" ]; then
      echo 'Error: Already authenticated' >&2
      exit 1
    fi
    mkdir -p "$sd"
    : > "$sd/valid"
    ;;
  *)
    exit 1
    ;;
esac
"#;
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
