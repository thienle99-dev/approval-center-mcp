# Approval Center MCP

Approval Center is a Go service that stores immutable proposals, requests a decision from Telegram approvers, and issues one-time execution claims to registered executors. A proposal never executes by itself. Executor-side enforcement is required for every protected action.

## Status

The service currently provides MCP proposal/status/list/policy/audit tools, SQLite persistence, YAML allow/deny policy matching, Telegram long polling and callback decisions, authenticated executor claims/results, and admin registration endpoints. The included SSH MCP patch is the enforcement adapter for `ssh_exec`. Review [SECURITY.md](SECURITY.md) before connecting production credentials.

## Run locally

Requirements: Go 1.26+, Docker Compose v2 for container builds. Create a private Docker network already shared with GoClaw, copy configuration, and set unique secrets:

```sh
cp .env.example .env
mkdir -p config
cp config/policies.example.yaml config/policies.yaml
docker network create goclaw-net
docker compose build
docker compose up -d
curl http://localhost:8080/healthz
```

The compose file does not publish a host port. From GoClaw's shared Docker network, configure the Streamable HTTP MCP URL as `http://approval-center-mcp:8080/mcp` and send `Authorization: Bearer <AGENT_TOKEN>`. Ensure `AGENT_TOKEN` belongs only to the intended requester. Admin and executor tokens are separate.

For local non-container development, set `DB_PATH`, `AGENT_TOKEN`, `ADMIN_TOKEN`, and `POLICY_FILE`, then run `go run ./cmd/approval-center`.

## Bootstrap identities

The configured `AGENT_TOKEN` bootstraps requester ID `agent`. Create additional requesters and executor identities with the admin bearer token. Tokens must be at least 32 characters; only SHA-256 token hashes are stored.

```sh
curl -X POST http://approval-center-mcp:8080/admin/executors \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"ID":"ssh-commander","Name":"SSH Commander","Token":"replace-with-a-long-random-executor-token"}'
curl -X POST http://approval-center-mcp:8080/admin/approvers \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"telegram_user_id":123456789,"display_name":"Operator","role":"operator"}'
```

The admin registration payload currently uses uppercase `ID`, `Name`, and `Token` JSON keys for executor registration (Go's default field names); requester registration uses `id`, `identity`, and `token`. Set `TELEGRAM_ALLOWED_USER_IDS` and `TELEGRAM_ALLOWED_CHAT_IDS` to numeric IDs. Use a separate bot token and ensure no other process polls it.

## Interfaces

MCP endpoint: `/mcp` (Streamable HTTP). Tools: `approval_request`, `approval_get_status`, `approval_list_requests`, `approval_get_policy`, `approval_get_audit`. No AI-accessible approval or override tool exists.

Executor endpoints use a bearer token registered for one executor:

- `POST /v1/executors/{executor_id}/claim` with `request_id`, `expected_action_digest`, `claim_attempt_id`.
- `POST /v1/executors/{executor_id}/result` with request/execution IDs, outcome, timestamps and bounded result reference/error summary.

The claim response returns the server-stored immutable specification. The executor must compare the requested operation against that response and execute only the returned specification. Outcomes: `EXECUTING`, `SUCCEEDED`, `FAILED`, `CANCELLED`, `INDETERMINATE`.

Admin endpoints are separate from MCP auth: `POST /admin/requesters`, `/admin/executors`, `/admin/approvers`. Keep the admin bearer credential out of GoClaw and executor containers.

## GoClaw and executors

Add an HTTP Streamable MCP server named `approval-center` at `http://approval-center-mcp:8080/mcp`, configure the agent bearer header, then grant access only to intended agents. Verify the installed GoClaw release supports Streamable HTTP and custom authorization headers. Availability of Approval Center does not protect GoClaw built-in execution tools; route sensitive work only through an executor with claim enforcement.

SSH integration uses executor ID `ssh-commander` and action type `ssh.command`; `target_id` must match the SSH inventory `server_id`, and parameters must include the exact `server_id` and `command` accepted by the adapter. See `examples/ssh-executor/README.md`. Coder systems must implement the same claim-before-execute flow; no existing Coder production path is modified here.

## Data, audit, recovery

SQLite uses WAL, foreign keys, a bounded single connection, unique idempotency keys and one unique claim per request. Back up the database only after a consistent SQLite backup/snapshot; include WAL handling. Restore while the service is stopped. Audit rows are append-only through application APIs, but a host administrator can alter the SQLite files, so this is not tamper-proof audit storage.

## Operations

The container runs as UID 10001 with a 256 MiB memory limit and 0.5 CPU limit. `/healthz` checks process liveness; `/readyz` checks SQLite readiness. Metrics and resource targets require load testing in the deployment environment; no measurements are claimed by this source delivery. Do not expose `/mcp` or `/admin` publicly. Telegram polling requires outbound HTTPS.

## Build and tests

```sh
gofmt -w ./cmd ./internal
go vet ./...
go test ./...
go test -race ./...
go build ./cmd/approval-center
docker compose build
```

See [SECURITY.md](SECURITY.md) for threat boundaries and known limitations. SQLite database administration, host OS privileges and SSH keys remain separate trust boundaries.
