# Architecture

```text
GoClaw MCP client
   | bearer requester identity
   v
Approval Center MCP/API ---- SQLite (proposal, decisions, claim, audit)
   |                                  ^
   | Telegram Bot API                 | independently authenticated executor
   v                                  |
Human approver -----------------------+ claim exact digest -> execute -> report
```

The service is a policy and authorization authority. It never executes shell, Kubernetes, Docker, Coder or database operations itself. A proposal is canonical JSON containing envelope version, action type, executor, target and parameters. Its SHA-256 digest is stored alongside requester, policy version, risk and expiry. Telegram callbacks are opaque, one-use server-side records. Executor claims are serialized through SQLite and constrained to one claim per proposal.

MCP is stateless Streamable HTTP, suitable for request/response tools and avoiding server-initiated MCP messages. Telegram approval is an independent channel. The executor uses a separate REST API because it must authenticate as a service identity and atomically consume authorization.

Policy matching checks all matching explicit denies before selecting the first matching allow policy in file order. Missing policy match denies. A production policy file should define targeted deny entries and narrow allow entries rather than broad wildcards.
