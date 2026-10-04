# docker-pass-cli

Minimal Unix-socket broker around the open-source
[Proton Pass CLI](https://github.com/protonpass/pass-cli). It is intended for
automation systems that must resolve scoped `pass://` or `proton://` references
without receiving the Proton Pass token or session.

The image contains two binaries:

- upstream `pass-cli`, built unchanged from a pinned commit;
- `proton-pass-broker`, a small Rust HTTP server listening on a Unix socket.

The SSH agent in `pass-cli` only implements the SSH agent protocol. This broker
is the separate interface for arbitrary Proton Pass item fields.

## Image

```text
ghcr.io/traktuner/docker-pass-cli:<pass-cli-version>-<broker-revision>
```

The image version follows Proton Pass CLI:

- `<version>-1`: first broker release for a Pass CLI version;
- `<version>-N`: broker-only revision while Pass CLI remains unchanged;
- `<version>`: moving alias for the newest broker revision on that Pass CLI;
- `latest`: newest supported Pass CLI and broker combination.

The initial pilot release supports `linux/amd64`. An arm64 release will follow
after the pilot uses a native arm64 CI runner instead of compiling the Rust
workspace through QEMU. The runtime uses Chainguard's
`cgr.dev/chainguard/glibc-dynamic`, runs as `1001:0`, and contains no shell or
package manager.

## Configuration

| Variable | Default |
| --- | --- |
| `PROTON_PASS_SOCKET` | `/run/proton-pass/broker.sock` |
| `PROTON_PASS_SESSION_DIR` | `/var/lib/proton-pass/session` |
| `PROTON_PASS_TOKEN_FILE` | `/run/secrets/proton_pass_agent_token` |
| `PROTON_PASS_CLI` | `/usr/local/bin/pass-cli` |
| `PROTON_PASS_COMMAND_TIMEOUT_SECONDS` | `60` |
| `PROTON_PASS_SESSION_CHECK_SECONDS` | `300` |

The token file must contain only a scoped Proton Pass agent token and must not
be accessible by group or others (`0400` or `0600`).

## API

The broker only listens on its Unix socket.

```http
POST /v1/resolve
Content-Type: application/json

{
  "reference": "proton://VAULT_NAME/ITEM_TITLE/FIELD",
  "reason": "Semaphore deploy karakeep on slvpdocker01"
}
```

Response:

```json
{"value":"resolved-secret"}
```

### Reference formats

| Scheme | Form | Resolution |
| --- | --- | --- |
| `proton://` | `proton://VAULT_NAME/ITEM_TITLE/FIELD` | pass-cli resolves the names at runtime (`--vault-name/--item-title/--field`). Recommended. |
| `pass://` | `pass://SHARE_ID/ITEM_ID/FIELD` | Forwarded as a positional URI. Legacy. |

Prefer `proton://`: vault names and item titles are stable across sessions,
while Share IDs are keyset-bound and differ between the user session and an
agent session, and change when the agent token is rotated. Vault names and item
titles used in a reference must be unique within their scope and contain no
whitespace or `/` (the reference is split on `/`).

Health:

```http
GET /healthz
```

The built-in Docker healthcheck client is:

```bash
proton-pass-broker healthcheck
```

## Isolated native scope verification

Trusted provisioning controllers can run the current native token scope checks
inside this existing image:

```bash
proton-pass-broker scoped \
  --session-dir /var/lib/proton-pass/session/infra-native-pass-scope-GENERATED \
  -- share list --output json
```

`PROTON_PASS_SESSION_DIR` remains the **normal parent session root**. Supply the
isolated directory through `--session-dir`. Never replace the parent environment
variable with the isolated directory for this command.

The command accepts only these exact argument lists:

- `info`
- `login`
- `share list --output json`
- `item list --vault-name t3-agents --output json`
- `logout --force`

The root and generated direct child must be owned by the executing UID with
mode `0700`. Paths must be canonical. The child name must start with
`infra-native-pass-scope-`. Existing child contents must not contain symlinks,
hardlinked files, foreign owners, or special files. These checks prevent mistaken
session selection. They do not sandbox malicious writers with the same UID.

Set `PROTON_PASS_AGENT_REASON` for every call. Supply the candidate token through
`PROTON_PASS_PERSONAL_ACCESS_TOKEN` only for `login`. The executor clears the
child environment and forwards that token only to the login child. It never
reads the normal broker token file or invokes automatic session recovery.

The internal deadline defaults to 60 seconds. Set
`PROTON_PASS_COMMAND_TIMEOUT_SECONDS` to an integer from 1 through 60 to shorten
it. After a deadline or output error, the executor signals its own child process
group and waits up to five additional seconds to reap the CLI process. Exit
`124` means that the deadline expired and termination was confirmed. Other
failures exit `1`. A process stuck in uninterruptible kernel sleep can prevent
confirmation; the executor reports failure and retains the session.

Metadata output is capped at 1 MiB. Authentication output and all CLI stderr are
discarded. Failed commands print only generic errors. The command never removes
session data. The controller must require successful inspection and logout
before it removes only its own generated directory.

`serve`, `healthcheck`, and the Unix-socket API keep their existing behavior.
This command adds no service, socket, dependency, or host namespace operation.

## Compose example

```yaml
services:
  proton-pass:
    image: ghcr.io/traktuner/docker-pass-cli:latest
    user: "1001:0"
    read_only: true
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    environment:
      PROTON_PASS_SESSION_DIR: /var/lib/proton-pass/session
      PROTON_PASS_KEY_PROVIDER: fs
      PROTON_PASS_TOKEN_FILE: /run/secrets/proton_pass_agent_token
      PROTON_PASS_SOCKET: /run/proton-pass/broker.sock
    volumes:
      - ./proton-pass/session:/var/lib/proton-pass/session
      - ./proton-pass/run:/run/proton-pass
      - ./proton-pass/agent-token:/run/secrets/proton_pass_agent_token:ro
    tmpfs:
      - /tmp:size=16m,mode=1777
    healthcheck:
      test: ["CMD", "/usr/local/bin/proton-pass-broker", "healthcheck"]
      interval: 30s
      timeout: 10s
      retries: 3
```

No TCP port, Docker socket, token, or session directory should be shared with
the consuming automation container. Share only `/run/proton-pass`.

## Agent setup

Create an audited agent with viewer access to the required item:

```bash
pass-cli agent create semaphore-infra --expiration 3m
pass-cli agent access grant semaphore-infra \
  --vault-name docker-secrets \
  --item-title karakeep \
  --role viewer
pass-cli agent renew semaphore-infra --expiration 3m
```

Use the renewed token. With `proton://` references no Share ID handling is
required: pass-cli resolves the vault name and item title against whatever
session is active, so the same reference works for the user session and the
agent session, and survives token rotation.

Legacy `pass://` references are keyset-bound: for an item-scoped grant, logging
in as the agent and running `pass-cli share list --output json` shows that
Proton creates a direct Item share with its own Share ID, and the reference must
use that agent Item share ID plus the unchanged Item ID, not the user's original
vault Share ID. This is exactly the fragility `proton://` avoids.

## Security properties

- Fixed `pass-cli` argument list per reference scheme; requests cannot execute
  arbitrary commands. Each reference is validated, then mapped to either
  `item view <pass-uri>` or `item view --vault-name … --item-title … --field …`.
- No secret cache.
- HTTP/API errors are generic. Child-process stderr is logged broker-side for
  diagnostics (expired token, undecryptable session, network) but never the
  secret value, which is read from stdout and is never logged.
- Request, reference, output, reason, and timeout limits.
- Agent reason is required for every read.
- CLI calls are serialized.
- Session and Proton connectivity are checked every five minutes through
  `pass-cli info --output json` and recreated from the scoped token when needed.
- A stale or undecryptable local session is purged only when pass-cli reports
  explicit local corruption (for example an AEAD/session-decryption error) or
  explicit server-side invalidation, then rebuilt from the token automatically.
  Transient DNS, connection, and timeout failures preserve the existing session
  instead of turning an outage into a forced re-login.
- The token is supplied only through `PROTON_PASS_PERSONAL_ACCESS_TOKEN` to the
  short-lived login child process and is never logged.

## Build

```bash
cargo test
docker build -t ghcr.io/traktuner/docker-pass-cli:dev .
```

The build compiles the configured Proton Pass CLI release from its exact
release-tag commit using the upstream committed lockfile. A scheduled GitHub
Actions workflow checks daily for a newer stable release and publishes the
corresponding `<version>-1`, `<version>`, and `latest` image tags only after the
normal tests, runtime verification, vulnerability scan, SBOM, and provenance
steps pass.
