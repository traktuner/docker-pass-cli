//! Trusted-controller scope verification. This does not expose another broker API.
use std::{env, fmt, fs, os::unix::fs::MetadataExt, path::Path, process::Stdio};

use anyhow::{Context, Result, bail};
use tokio::{io::AsyncReadExt, process::Command, time::timeout};

use crate::{Config, validate_reason};

const SCOPE_PREFIX: &str = "infra-native-pass-scope-";
const MAX_METADATA_BYTES: u64 = 1024 * 1024;

#[derive(Debug)]
pub(super) struct DeadlineExceeded;

impl fmt::Display for DeadlineExceeded {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Scoped pass-cli deadline exceeded")
    }
}

impl std::error::Error for DeadlineExceeded {}

pub(super) async fn run(config: &Config, session: &Path, arguments: &[String]) -> Result<()> {
    let args: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let metadata = match args.as_slice() {
        ["info"]
        | ["share", "list", "--output", "json"]
        | [
            "item",
            "list",
            "--vault-name",
            "t3-agents",
            "--output",
            "json",
        ] => true,
        ["login"] | ["logout", "--force"] => false,
        _ => bail!("Unsupported scope command"),
    };
    if !(1..=60).contains(&config.command_timeout.as_secs()) {
        bail!("Scope deadline must be between 1 and 60 seconds");
    }
    validate_session(&config.session_dir, session)?;
    let reason = env::var("PROTON_PASS_AGENT_REASON").context("Scope audit reason is required")?;
    validate_reason(&reason)?;

    let mut command = Command::new(&config.pass_cli);
    command
        .args(&args)
        .env_clear()
        .env("HOME", "/var/lib/proton-pass")
        .env("PROTON_PASS_SESSION_DIR", session)
        .env("PROTON_PASS_KEY_PROVIDER", "fs")
        .env("PROTON_PASS_AGENT_REASON", reason)
        .env("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .kill_on_drop(true);
    if args == ["login"] {
        let token = env::var("PROTON_PASS_PERSONAL_ACCESS_TOKEN")
            .context("Scope login candidate is required")?;
        if token.trim().is_empty() {
            bail!("Scope login candidate is required");
        }
        command.env("PROTON_PASS_PERSONAL_ACCESS_TOKEN", token);
    }
    for proxy in ["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"] {
        if let Ok(value) = env::var(proxy) {
            command.env(proxy, value);
        }
    }

    let deadline = std::time::Instant::now() + config.command_timeout;
    let mut child = command.spawn().context("Unable to start scoped pass-cli")?;
    let pid = i32::try_from(child.id().context("Scoped pass-cli has no process ID")?)?;
    let stdout = child
        .stdout
        .take()
        .context("Scoped output pipe is absent")?;
    // Read before reaping: the leader PID remains reserved while its group can
    // hold the output pipe. A timeout can signal only this owned process group.
    let result = timeout(config.command_timeout, async {
        let mut output = Vec::new();
        stdout
            .take(MAX_METADATA_BYTES + 1)
            .read_to_end(&mut output)
            .await?;
        if output.len() as u64 > MAX_METADATA_BYTES {
            bail!("Scoped output exceeds the limit");
        }
        let status = child.wait().await?;
        Ok::<_, anyhow::Error>((status, output))
    })
    .await;

    let (status, output) = match result {
        Ok(Ok(output)) => output,
        failure => {
            // No host PID discovery or namespace changes. This process created
            // the group, and has not reaped its leader on these error paths.
            if unsafe { libc::kill(-pid, libc::SIGKILL) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(error).context("Unable to stop scoped pass-cli");
                }
            }
            timeout(std::time::Duration::from_secs(5), child.wait())
                .await
                .context("Unable to confirm scoped process termination")??;
            return match failure {
                Err(_) => Err(DeadlineExceeded.into()),
                Ok(Err(error)) => Err(error),
                Ok(Ok(_)) => unreachable!(),
            };
        }
    };
    if !status.success() {
        bail!("Scoped pass-cli failed");
    }
    if metadata {
        write_bounded(libc::STDOUT_FILENO, &output, deadline)?;
    }
    Ok(())
}

fn validate_session(root: &Path, session: &Path) -> Result<()> {
    let name = session
        .file_name()
        .and_then(|name| name.to_str())
        .context("Scope directory name is invalid")?;
    let suffix = name.strip_prefix(SCOPE_PREFIX).unwrap_or("");
    if suffix.is_empty()
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        || session.as_os_str() != root.join(name).as_os_str()
    {
        bail!("Scope must be a generated direct child of the normal session root");
    }
    for path in [root, session] {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o7777 != 0o700
            || fs::canonicalize(path)?.as_os_str() != path.as_os_str()
        {
            bail!("Scope paths must be private owned directories without symlinks");
        }
    }
    // The caller owns these private directories. Refuse existing links into the
    // normal session. These checks do not sandbox hostile same-UID writers.
    let mut pending = vec![session.to_path_buf()];
    let mut entries = 0;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            let metadata = fs::symlink_metadata(&path)?;
            entries += 1;
            if entries > 4096 || metadata.uid() != unsafe { libc::geteuid() } {
                bail!("Scope contents are invalid");
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if !metadata.is_file() || metadata.nlink() != 1 {
                bail!("Scope contents must not contain links or special files");
            }
        }
    }
    Ok(())
}

// Tokio stdout uses a blocking task. Cancelling its future does not cancel the
// write, and runtime shutdown can still wait forever. Use nonblocking writes
// after the CLI is reaped, with the original deadline and no detached tasks.
fn write_bounded(fd: i32, output: &[u8], deadline: std::time::Instant) -> Result<()> {
    let original_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if original_flags < 0
        || unsafe { libc::fcntl(fd, libc::F_SETFL, original_flags | libc::O_NONBLOCK) } < 0
    {
        bail!("Unable to configure scoped output");
    }
    let result = (|| {
        let mut remaining_output = output;
        while !remaining_output.is_empty() {
            let remaining_time = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining_time.is_zero() {
                return Err(DeadlineExceeded.into());
            }
            let written = unsafe {
                libc::write(fd, remaining_output.as_ptr().cast(), remaining_output.len())
            };
            if written > 0 {
                remaining_output = &remaining_output[written as usize..];
                continue;
            }
            if written == 0 {
                bail!("Scoped output did not progress");
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if error.kind() != std::io::ErrorKind::WouldBlock {
                return Err(error.into());
            }
            let mut descriptor = libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            let milliseconds = remaining_time.as_millis().clamp(1, i32::MAX as u128) as i32;
            if unsafe { libc::poll(&mut descriptor, 1, milliseconds) } < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    return Err(error.into());
                }
            }
        }
        Ok(())
    })();
    if unsafe { libc::fcntl(fd, libc::F_SETFL, original_flags) } < 0 {
        bail!("Unable to restore scoped output flags");
    }
    result
}

pub(super) fn report_failure(message: &[u8]) {
    // Exit status is authoritative. Diagnostics are best-effort and bounded,
    // including when stderr shares a full stdout pipe through shell redirection.
    let _ = write_bounded(
        libc::STDERR_FILENO,
        message,
        std::time::Instant::now() + std::time::Duration::from_millis(100),
    );
}
