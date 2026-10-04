use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    process::{Command, Output},
    time::{Duration, Instant},
};

struct Fixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    session: PathBuf,
    executable: PathBuf,
}

impl Fixture {
    fn new(script: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap().join("session");
        let session = root.join("infra-native-pass-scope-fixture");
        fs::create_dir_all(&session).unwrap();
        for path in [&root, &session] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(root.join("normal-session-marker"), "retain").unwrap();
        fs::write(session.join("scope-marker"), "retain").unwrap();
        let executable = directory.path().join("fake-pass-cli");
        fs::write(&executable, format!("#!/bin/sh\n{script}\n")).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            _directory: directory,
            root,
            session,
            executable,
        }
    }

    fn command(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_proton-pass-broker"));
        command
            .env_clear()
            .env("PROTON_PASS_SESSION_DIR", &self.root)
            .env("PROTON_PASS_CLI", &self.executable)
            .env("PROTON_PASS_AGENT_REASON", "Verify isolated native scope")
            .env("PROTON_PASS_COMMAND_TIMEOUT_SECONDS", "1")
            .arg("scoped")
            .arg("--session-dir")
            .arg(&self.session)
            .arg("--")
            .args(arguments);
        command
    }

    fn run(&self, arguments: &[&str]) -> Output {
        self.command(arguments).output().unwrap()
    }

    fn assert_retained(&self) {
        assert!(self.root.join("normal-session-marker").exists());
        assert!(self.session.join("scope-marker").exists());
    }
}

#[test]
fn scoped_metadata_uses_only_the_private_session_and_audit_environment() {
    let test = Fixture::new(
        r#"test "$PROTON_PASS_AGENT_REASON" = 'Verify isolated native scope' || exit 9
[ -z "$PROTON_PASS_PERSONAL_ACCESS_TOKEN" ] || exit 10
[ -z "$UNRELATED_CREDENTIAL" ] || exit 11
printf '%s\n' "$@" > "$PROTON_PASS_SESSION_DIR/arguments"
printf '{"fixture":"metadata"}\n'"#,
    );
    for arguments in [
        vec!["info"],
        vec!["share", "list", "--output", "json"],
        vec![
            "item",
            "list",
            "--vault-name",
            "t3-agents",
            "--output",
            "json",
        ],
    ] {
        let output = test
            .command(&arguments)
            .env(
                "PROTON_PASS_PERSONAL_ACCESS_TOKEN",
                "SYNTHETIC_TOKEN_MARKER",
            )
            .env("UNRELATED_CREDENTIAL", "SYNTHETIC_UNRELATED_MARKER")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, b"{\"fixture\":\"metadata\"}\n");
        assert_eq!(
            fs::read_to_string(test.session.join("arguments")).unwrap(),
            format!("{}\n", arguments.join("\n"))
        );
        test.assert_retained();
    }
}

#[test]
fn scoped_login_only_passes_the_candidate_and_suppresses_authentication_output() {
    let test = Fixture::new(
        r#"test "$1" = login || exit 9
test "$PROTON_PASS_PERSONAL_ACCESS_TOKEN" = SYNTHETIC_TOKEN_MARKER || exit 10
printf '%s\n' "$PROTON_PASS_PERSONAL_ACCESS_TOKEN"
printf '%s\n' "$PROTON_PASS_PERSONAL_ACCESS_TOKEN" >&2"#,
    );
    let output = test
        .command(&["login"])
        .env(
            "PROTON_PASS_PERSONAL_ACCESS_TOKEN",
            "SYNTHETIC_TOKEN_MARKER",
        )
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("SYNTHETIC_TOKEN_MARKER"));
    test.assert_retained();
}

#[test]
fn scoped_logout_has_no_candidate_or_output() {
    let test = Fixture::new(
        r#"[ -z "$PROTON_PASS_PERSONAL_ACCESS_TOKEN" ] || exit 9
printf 'SYNTHETIC_LOGOUT_MARKER\n'"#,
    );
    let output = test.run(&["logout", "--force"]);
    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty());
    test.assert_retained();
}

#[test]
fn scoped_rejects_other_commands_before_spawn() {
    let test = Fixture::new("touch \"$PROTON_PASS_SESSION_DIR/spawned\"");
    for arguments in [
        vec!["item", "view", "proton://vault/item/password"],
        vec![
            "item",
            "list",
            "--vault-name",
            "docker-secrets",
            "--output",
            "json",
        ],
        vec!["login", "--token", "SYNTHETIC_ARG_MARKER"],
        vec!["info", "--output", "json"],
        vec!["logout"],
        vec!["share", "list", "--output", "json", "--extra"],
        vec!["/bin/sh"],
    ] {
        let output = test.run(&arguments);
        assert!(!output.status.success());
        assert!(!test.session.join("spawned").exists());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("SYNTHETIC_ARG_MARKER"));
        test.assert_retained();
    }
}

#[test]
fn scoped_rejects_normal_outside_nested_symlink_and_nonprivate_sessions() {
    let mut test = Fixture::new("touch \"$PROTON_PASS_SESSION_DIR/spawned\"");
    let original = test.session.clone();
    let outside = test
        .root
        .parent()
        .unwrap()
        .join("infra-native-pass-scope-outside");
    fs::create_dir(&outside).unwrap();
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o700)).unwrap();
    let nested = original.join("infra-native-pass-scope-nested");
    fs::create_dir(&nested).unwrap();
    let link = test.root.join("infra-native-pass-scope-link");
    symlink(&original, &link).unwrap();
    for path in [&test.root.clone(), &outside, &nested, &link] {
        test.session = path.clone();
        assert!(!test.run(&["info"]).status.success());
        assert!(!original.join("spawned").exists());
        assert!(!test.root.join("spawned").exists());
        assert!(!outside.join("spawned").exists());
        assert!(!nested.join("spawned").exists());
    }
    test.session = original;
    for mode in [0o755, 0o770, 0o777] {
        fs::set_permissions(&test.session, fs::Permissions::from_mode(mode)).unwrap();
        assert!(!test.run(&["info"]).status.success());
        assert!(!test.session.join("spawned").exists());
    }
    test.assert_retained();
}

#[test]
fn scoped_rejects_symlinks_within_the_isolated_session() {
    let test = Fixture::new("touch \"$PROTON_PASS_SESSION_DIR/spawned\"");
    symlink(&test.root, test.session.join(".session")).unwrap();
    assert!(!test.run(&["info"]).status.success());
    assert!(!test.session.join("spawned").exists());
    test.assert_retained();
}

#[test]
fn scoped_failure_never_echoes_cli_output_and_retains_both_sessions() {
    let test = Fixture::new(
        "printf 'SYNTHETIC_STDOUT_MARKER\\n'; printf 'SYNTHETIC_STDERR_MARKER\\n' >&2; exit 7",
    );
    let output = test.run(&["info"]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(!error.contains("SYNTHETIC_STDOUT_MARKER"));
    assert!(!error.contains("SYNTHETIC_STDERR_MARKER"));
    test.assert_retained();
}

#[test]
fn scoped_deadline_kills_the_actual_cli_and_preserves_its_session() {
    let test = Fixture::new("echo $$ > \"$PROTON_PASS_SESSION_DIR/pid\"; exec /bin/sleep 30");
    let started = Instant::now();
    let output = test.run(&["info"]);
    assert_eq!(output.status.code(), Some(124), "{output:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
    let pid: i32 = fs::read_to_string(test.session.join("pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_eq!(unsafe { libc::kill(pid, 0) }, -1, "CLI survived deadline");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
    test.assert_retained();
}

#[test]
fn scoped_rejects_unbounded_deadlines_and_missing_login_token_before_spawn() {
    let test = Fixture::new("touch \"$PROTON_PASS_SESSION_DIR/spawned\"");
    for value in ["0", "61", "invalid"] {
        let output = test
            .command(&["info"])
            .env("PROTON_PASS_COMMAND_TIMEOUT_SECONDS", value)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(!test.session.join("spawned").exists());
    }
    assert!(!test.run(&["login"]).status.success());
    assert!(!test.session.join("spawned").exists());
    test.assert_retained();
}

#[test]
fn scoped_deadline_also_bounds_a_controller_that_stops_reading_metadata() {
    let test = Fixture::new("/usr/bin/head -c 262144 /dev/zero");
    let mut child = test
        .command(&["share", "list", "--output", "json"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    // Keep the reader open without draining it. Command::output() cannot
    // reproduce controller backpressure because it drains the pipe itself.
    let _reader = child.stdout.take().unwrap();
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > Duration::from_secs(4) {
            child.kill().unwrap();
            break child.wait().unwrap();
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(
        status.code(),
        Some(124),
        "Metadata delivery exceeded its deadline"
    );
    test.assert_retained();
}

#[test]
fn scoped_rejects_hardlinked_session_files() {
    let test = Fixture::new("touch \"$PROTON_PASS_SESSION_DIR/spawned\"");
    fs::hard_link(
        test.root.join("normal-session-marker"),
        test.session.join("shared-file"),
    )
    .unwrap();
    assert!(!test.run(&["info"]).status.success());
    assert!(!test.session.join("spawned").exists());
    test.assert_retained();
}

#[test]
fn scoped_output_limit_stops_the_cli_without_forwarding_partial_output() {
    let test = Fixture::new(
        "echo $$ > \"$PROTON_PASS_SESSION_DIR/pid\"; exec /usr/bin/head -c 1048577 /dev/zero",
    );
    let output = test.run(&["info"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty());
    let pid: i32 = fs::read_to_string(test.session.join("pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
    test.assert_retained();
}
