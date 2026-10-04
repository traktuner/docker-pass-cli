# Project traps

- CONSTRAINT: Never purge `<session_dir>/.session` merely because `pass-cli test`
  and a subsequent `login` fail. A transient DNS or connection outage makes
  `test` fail while `login` correctly returns `Already authenticated`; deleting
  the still-valid session then converts a network blip into a forced re-login.
  Purge only after pass-cli explicitly reports local AEAD/session-decryption
  corruption, and retain the transient-network regression test
  (`broker/src/main.rs`).
- CONSTRAINT: Validate the broker against the exact pinned pass-cli command
  surface, not only `pass-cli --version`. Pass CLI 2.2 removed the former `test`
  command, so an image could pass identity checks while every broker healthcheck
  remained unhealthy. Use the authenticated `info --output json` probe and keep
  `info --help` in the image-runtime CI check (`broker/src/main.rs`,
  `.github/workflows/container.yml`).
- CONSTRAINT: Keep `PROTON_PASS_SESSION_DIR` as the normal parent root when
  calling `proton-pass-broker scoped`; pass the generated child only through
  `--session-dir`. The Infra role previously passed the isolated child through
  the environment for direct `pass-cli` calls. Reusing that invocation selects
  the wrong parent and must fail closed. Never remove either session to work
  around validation (`broker/src/scoped.rs`, Infra `roles/native-ai/tasks/pass-scope.yml`).
- CONSTRAINT: Bound metadata delivery with nonblocking writes inside the same
  scoped deadline. A timeout around Tokio stdout does not stop its blocking
  write task, so runtime shutdown can hang after the CLI was reaped. The real
  CLI regression keeps a pipe reader open without draining it; preserve that
  test (`broker/src/scoped.rs`, `broker/tests/scoped.rs`).
