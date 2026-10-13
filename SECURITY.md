# Security model and limitations

## Trust boundaries

```text
GoClaw requester --bearer token--> MCP proposal API
                                         |
                                         v
                                  SQLite + policy
                                         |
                              Telegram human decision
                                         |
Trusted executor --own bearer--> atomic claim API --> exact stored envelope
        |                                                |
        +---------------- execute claimed action <-------+
```

The agent may propose but cannot approve or claim. Telegram user and chat numeric IDs plus registered approver rows authorize human decisions. Executor credentials are independently registered. A claim binds request, executor and digest and has a unique database constraint. Approval Center cannot enforce approval on GoClaw built-in tools unless they are intercepted or replaced by an integrated executor.

## Threat controls

- Default deny and explicit deny precedence; YAML policies are administrator-controlled.
- Proposals include canonical Go JSON serialization and SHA-256 digest. Map keys are serialized deterministically by `encoding/json`.
- Approval callback tokens are random, stored server-side, expiration-bound and consumed in a transaction. Distinct approver IDs are enforced by a uniqueness constraint.
- Executors receive the stored action on successful one-time claim; they must not use caller-supplied commands after that point.
- Requester and executor bearer tokens are stored as SHA-256 hashes. Use random tokens with at least 256 bits of entropy and TLS between hosts.
- HTTP request bodies and output/error references are bounded. Secrets are rejected by common field/value heuristics; avoid putting credentials in actions or reason text.

## Known limitations requiring review before production

- Policy file is read at startup; there is no hot reload or authenticated policy update API yet.
- The REST admin API provides identity registration but does not yet provide disable/list/rotation operations.
- Telegram long-poll offsets are in memory. Restart may replay an update; one-time callback consumption and decision uniqueness prevent replayed approvals.
- Telegram notification delivery is attempted asynchronously; a durable retry queue and notification-failed UI are not implemented yet.
- No rate limiter, metrics endpoint, external audit integrity chain, retention worker, or full JSON Schema validator is included yet.
- Secret detection is heuristic and cannot prove arbitrary command strings contain no secret. Keep secrets out of proposed commands and notification text.
- A successful claim does not prove the remote action executed. Executors must report outcomes; uncertain execution must report `INDETERMINATE` and must not retry automatically.
- This repository's service does not configure or elevate SSH/Kubernetes permissions. Executor OS and remote identity controls remain essential.

Do not describe this initial implementation as production-ready until these limitations are addressed and Telegram, Docker, GoClaw, and executor integration tests pass in the target environment.
