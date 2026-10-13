# SSH Commander integration

The SSH MCP adapter must claim every `ssh.command` before opening an SSH session. It should submit the request ID, digest and fresh claim attempt ID to `POST /v1/executors/ssh-commander/claim`, then compare the returned envelope's `action_type`, `target_id`, `executor_id`, `parameters.server_id`, and `parameters.command` to the requested tool input. Execute only the server-returned command and target. On a timeout with an uncertain remote result, report `INDETERMINATE`; never automatically repeat the command.

The integration patch is applied to the existing `/root/ssh-mcp` tree during the VPS staging step. Until that patch is built and the running SSH MCP is replaced, its existing `ssh_exec` remains an uncontrolled path and the service alone does not protect it.
