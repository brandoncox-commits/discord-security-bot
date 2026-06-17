# Bams Modmin Tools

A public, multi-server Discord moderation & security bot for incident response
and server hardening. Anyone can invite it to their own server — it stores no
per-server config and works out of the box.

Commands are modern **slash commands** (`/`) — they autocomplete, validate
arguments, and are hidden in the picker from members who lack the Administrator
permission.

**[➕ Add to your server](https://discord.com/api/oauth2/authorize?client_id=1516798418587222117&scope=bot+applications.commands&permissions=805399604)**
· [Terms of Service](https://brandoncox-commits.github.io/discord-security-bot/terms-of-service)
· [Privacy Policy](https://brandoncox-commits.github.io/discord-security-bot/privacy-policy)

## Commands

All commands require the **Administrator** permission.

| Command | What it does |
|---|---|
| `/help` | Lists every command and what it does. |
| `/bulk-purge-user <user>` | Bans the user, deletes their messages from the last 14 days across all channels & threads, and removes any webhooks they created plus those webhooks' messages. |
| `/audit-permissions` | Audits every role, `@everyone`, and all integrations/apps for dangerous permissions. Colour-coded embed. |
| `/purge-webhooks` | Deletes every webhook in the server (closes spam backdoors). Logs names to `#mod-logs`. |
| `/panic <lock\|unlock>` | Freezes/unfreezes all text channels for `@everyone` during a raid. |
| `/wipe-invites` | Revokes all active invite links so banned users can't rejoin. |
| `/trace-app <app> [scan_messages]` | Finds the human(s) behind an app/bot — the integration installer and/or whoever invoked a user-installed app to post — so you can `/bulk-purge-user` them. Report-only. |

### `panic` lock/unlock behaviour

`lock` denies posting/reacting for `@everyone` across all text channels, but
**skips channels that are already read-only** for `@everyone` and records them.
It saves each locked channel's exact prior overwrite to `panic_state.json`.
`unlock` restores every locked channel to its **exact** pre-lock state and
leaves the recorded read-only channels untouched, so a lockdown can never
accidentally open a channel that was meant to stay restricted. Locking twice is
refused until you unlock (to protect the saved state).

### `trace-app` — linking an app to a user

Discord exposes two reliable links from a malicious app to a person:
its **integration installer** (`integration.user`) and, for user-installed
apps, the **invoker** recorded on each message (`interaction_metadata.user`).
`/trace-app` gathers both and reports candidate user IDs; it does **not** ban
automatically (a false match shouldn't nuke an innocent user). Confirm, then run
`/bulk-purge-user`. Classic bots that post on their own (no interaction) may only
be traceable via Server Settings → Integrations.

## How logging works (multi-server friendly)

The bot logs actions to a channel named **`#mod-logs`** in whichever server the
command was run. Each server that installs the bot just needs to create a
channel called `mod-logs` (or the bot silently skips logging). No per-server
setup or database required.

## Hosting setup (bot owner)

1. **Create the application** at <https://discord.com/developers/applications>.
   - Under **Bot**, copy the token.
   - Enable the **Server Members Intent** (Privileged Gateway Intents). The
     Message Content and Presence intents are **not** required.
   - Under **Installation**, enable **Guild Install** with scopes
     `bot` + `applications.commands`.
2. **Configure & run:**
   ```bash
   cp .env.example .env        # then paste your BOT_TOKEN
   pip install -r requirements.txt
   python bot.py
   ```
   Leave `DEV_GUILD_ID` blank for global command sync. Set it to a server ID to
   sync commands to that one server instantly (useful while testing).

## Install link (server admins)

**Least-privilege (recommended):**
```
https://discord.com/api/oauth2/authorize?client_id=1516798418587222117&scope=bot+applications.commands&permissions=805399604
```
That permission integer grants exactly what the commands need:
View Channels, Send Messages, Embed Links, Read Message History,
Manage Messages, Manage Channels, Manage Roles, Manage Webhooks,
Manage Server, and Ban Members.

**Simplest (Administrator):** if you'd rather grant a single permission, use
`permissions=8` (Administrator). This is broader than necessary —
least-privilege is preferred.

> Self-hosting your own instance? Replace the `client_id` above with your own
> application's Client ID (Developer Portal → General Information).

## Legal

- **Terms of Service:** <https://brandoncox-commits.github.io/discord-security-bot/terms-of-service>
- **Privacy Policy:** <https://brandoncox-commits.github.io/discord-security-bot/privacy-policy>

> The bot's role must sit **above** the roles/members it acts on, or Discord
> will reject bans and permission edits with a `Forbidden` error. The bot
> handles these gracefully and reports which channels/users it couldn't touch.

## Notes & limits

- **14-day window:** Discord only allows *bulk* message deletion for messages
  younger than 14 days. `/bulk-purge-user` deliberately ignores older messages
  to stay fast and within API rate limits.
- **Graceful degradation:** every command reports how many channels/items it
  had to skip due to missing permissions instead of failing outright.
