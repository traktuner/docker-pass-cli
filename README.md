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
ghcr.io/traktuner/docker-pass-cli:2.1.2-1
```

Supported platforms are `linux/amd64` and `linux/arm64`. The runtime uses
Chainguard's `cgr.dev/chainguard/glibc-dynamic`, runs as `1001:0`, and contains
no shell or package manager.

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
    image: ghcr.io/traktuner/docker-pass-cli:2.1.2-1
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
  --vault-name Infrastructure \
  --item-title Karakeep \
  --role viewer
```

Use stable Share ID and Item ID references in deployed configuration.

## Security properties

- Fixed `pass-cli` argument list; requests cannot execute arbitrary commands.
- No secret cache.
- Child-process stderr is discarded and API errors are generic.
- Request, reference, output, reason, and timeout limits.
- Agent reason is required for every read.
- CLI calls are serialized.
- Session is checked every five minutes and recreated from the scoped token.
- The token is only supplied to the login child process.

## Build

```bash
cargo test
docker build -t ghcr.io/traktuner/docker-pass-cli:dev .
```

The build compiles Proton Pass CLI `2.1.2` from commit
`b0a15d41dabc4e71d2cc3cf6710595a4271355b9` using its committed lockfile.
