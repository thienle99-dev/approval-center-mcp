# Integration guide

## GoClaw MCP client

Register a Streamable HTTP MCP server named `approval-center`, URL `http://approval-center-mcp:8080/mcp`, with `Authorization: Bearer <requester-token>`. Confirm the installed GoClaw version supports Streamable HTTP and custom headers. Give the agent only proposal and read access. The server does not add the approval tool to built-in shell tools and cannot intercept them.

## Executor sequence

1. Agent proposes an exact action and target.
2. Approval Center stores the canonical envelope and returns request ID/digest.
3. A Telegram approver makes a verified decision.
4. Executor polls status through the requester integration or is otherwise notified by its caller.
5. Executor calls claim with request ID, exact digest and unique attempt ID.
6. Executor validates returned envelope against its own allowed operation schema and executes only returned fields.
7. Executor reports `EXECUTING` then a terminal result. If remote outcome is uncertain, report `INDETERMINATE`; do not retry automatically.

The included claim service does not itself invoke execution and does not prove an executor is well behaved. Enforcement must be in the only route to the privileged operation.
