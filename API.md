# API reference

All endpoints are internal and require HTTPS when crossing hosts. MCP and admin routes use different bearer credentials. Executor bearer tokens are independently registered and scoped to one executor ID.

## MCP

`POST /mcp` uses the official Go MCP SDK Streamable HTTP transport. Tools:

| Tool | Purpose |
| --- | --- |
| `approval_request` | Save a proposal and notify configured Telegram approver chats. It does not run the action. |
| `approval_get_status` | Read the caller's request state. |
| `approval_list_requests` | List the caller's latest 100 requests. |
| `approval_get_policy` | Read configured policy summaries. |
| `approval_get_audit` | Read redacted event fields for the caller's request. |

`approval_request` fields: `action_type`, `target_id`, `executor_id`, `action_specification` object, `reason`, optional `requested_timeout`, and `idempotency_key`. Reuse of a key with different content is rejected.

## Executor API

`POST /v1/executors/{executor_id}/claim` accepts:

```json
{"request_id":"...","expected_action_digest":"...","claim_attempt_id":"unique-attempt-id"}
```

On success returns the immutable stored envelope. The endpoint rejects non-approved, expired, mismatched, unregistered, or already claimed requests.

`POST /v1/executors/{executor_id}/result` accepts request/execution IDs, outcome, timestamps, and bounded result/error references. Outcome must be `EXECUTING`, `SUCCEEDED`, `FAILED`, `CANCELLED`, or `INDETERMINATE`.

## Admin API

All admin routes require the separate `ADMIN_TOKEN`.

- `POST /admin/requesters`: `{ "id", "identity", "token" }`
- `POST /admin/executors`: `{ "ID", "Name", "Token" }`
- `POST /admin/approvers`: `{ "telegram_user_id", "display_name", "role" }`

Registration returns only the identity; tokens are never returned or stored in plaintext. Admin credential rotation and identity disable/list endpoints are not implemented yet.

## Status endpoints

- `GET /healthz`: process liveness.
- `GET /readyz`: SQLite connectivity.
