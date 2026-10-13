# Telegram setup

Create a dedicated Telegram bot and configure `TELEGRAM_BOT_TOKEN`, `TELEGRAM_ALLOWED_USER_IDS`, and `TELEGRAM_ALLOWED_CHAT_IDS`. IDs must be numeric; chat IDs can be negative for groups. Register each human approver through `POST /admin/approvers`. Usernames are never used for authorization. Keep this bot token exclusive to one polling service.

The bot sends the full action envelope, reason, target, risk and expiry with Approve/Reject buttons. Messages exceeding the implementation's bounded payload are rejected rather than truncated. Callback payloads contain an opaque request and random token; the corresponding token is stored with request, decision, expiry and single-use state. The callback must arrive from an allowlisted user and chat and a registered approver.

A failed Telegram send leaves the request pending; this initial implementation does not yet persist retry scheduling or expose a durable delivery-failure status. Check service logs and ensure the bot can send messages to every configured chat.
