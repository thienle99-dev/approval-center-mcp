# SQLite schema

The process enables WAL, foreign keys, and a 5-second busy timeout, and limits SQLite to one open connection to serialize state changes. Schema initialization is recorded in `schema_migrations` version 1.

Tables: `requesters`, `executors`, `approvers`, `approval_requests`, `approval_decisions`, `telegram_callbacks`, `execution_claims`, `execution_results`, and `audit_events`. Requester/idempotency, approver/request decision, callback token, executor claim attempt, one claim per request, and execution ID constraints prevent duplicate state transitions. Foreign keys link request lifecycle rows.

Back up using SQLite's online backup facility or stop the service and copy the database plus any WAL files. Keep database permissions restricted to service UID. Audit event rows do not include action parameters in list/audit MCP responses. The local SQLite file remains editable by a host administrator.
