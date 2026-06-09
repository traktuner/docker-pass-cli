# docker-pass-cli

Minimal Unix-socket broker around the open-source
[Proton Pass CLI](https://github.com/protonpass/pass-cli). It is intended for
automation systems that must resolve scoped `pass://` references without
receiving the Proton Pass token or session.

The image contains two binaries:

- upstream `pass-cli`, built unchanged from a pinned commit;
- `proton-pass-broker`, a small Rust HTTP server listening on a Unix socket.

The SSH agent in `pass-cli` only implements the SSH agent protocol. This broker
is the separate interface for arbitrary Proton Pass item fields.

## Image

```text
ghcr.io/traktuner/docker-pass-cli:2.1.2-3
```

The image version follows Proton Pass CLI:

- `2.1.2-3`: current broker revision containing Pass CLI 2.1.2;
- `2.1.2-2`: immutable broker revision containing Pass CLI 2.1.2;
- `2.1.2-1`: immutable first broker release containing Pass CLI 2.1.2;
- `2.1.2-2`: broker-only fix while Pass CLI remains 2.1.2;
- `2.1.2`: moving alias for the newest broker revision on Pass CLI 2.1.2;
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
  "reference": "pass://SHARE_ID/ITEM_ID/FIELD",
  "reason": "Semaphore deploy karakeep on slvpdocker01"
}
```

Response:

```json
{"value":"resolved-secret"}
```

Health:

```http
GET /healthz
```

The built-in Docker healthcheck client is:

```bash
proton-pass-broker healthcheck
```

## Compose example

```yaml
services:
  proton-pass:
    image: ghcr.io/traktuner/docker-pass-cli:2.1.2-3
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

Use the renewed token. For an item-scoped grant, log in as the agent and run
`pass-cli share list --output json`: Proton creates a direct Item share with
its own Share ID. Deployed references must use that agent Item share ID plus
the unchanged Item ID, not the user's original vault Share ID.

## Security properties

- Fixed `pass-cli` argument list; requests cannot execute arbitrary commands.
- No secret cache.
- Child-process stderr is discarded and API errors are generic.
- Request, reference, output, reason, and timeout limits.
- Agent reason is required for every read.
- CLI calls are serialized.
- Session is checked every five minutes and recreated from the scoped token.
- The token is supplied only through `PROTON_PASS_PERSONAL_ACCESS_TOKEN` to the
  short-lived login child process and is never logged.

## Build

```bash
cargo test
docker build -t ghcr.io/traktuner/docker-pass-cli:dev .
```

The build compiles Proton Pass CLI `2.1.2` from commit
`b0a15d41dabc4e71d2cc3cf6710595a4271355b9` using its committed lockfile.
