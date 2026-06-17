"""
Discord Moderation & Security Bot
=================================

A slash-command (application command) bot focused on incident response and
server hardening. Built on discord.py 2.x.

Commands
--------
/bulk-purge-user <user>   Ban a user and delete their messages from the last 14 days.
/audit-permissions        Audit roles, @everyone, and integrations for dangerous permissions.
/purge-webhooks           Delete every webhook in the server (closes spam backdoors).
/panic <lock|unlock>      Freeze / unfreeze all text channels during a raid.
/wipe-invites             Delete all active invite links.

All commands require the Administrator permission and are hidden from non-admins.

Setup
-----
1. Copy `.env.example` to `.env` and fill in the values.
2. pip install -r requirements.txt
3. python bot.py

Required privileged intents (enable in the Discord Developer Portal):
  - Server Members Intent  (for member lookups / bans)
  - Message Content Intent is NOT required for these commands.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import discord
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
# Channel where audit/security actions are logged. Optional but recommended.
MOD_LOG_CHANNEL_ID = int(os.getenv("MOD_LOG_CHANNEL_ID", "0") or "0")
# Optional: restrict slash-command sync to a single guild for instant updates
# during development. Leave unset for global (can take up to an hour to appear).
DEV_GUILD_ID = int(os.getenv("DEV_GUILD_ID", "0") or "0")

# Discord only allows *bulk* deletion of messages younger than 14 days.
BULK_DELETE_MAX_AGE = timedelta(days=14)

# Persisted panic-lock state lives next to this file, keyed by guild ID, so that
# /panic unlock can restore each channel to its EXACT pre-lock overwrite values.
STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "panic_state.json")

# The @everyone overwrites that /panic toggles.
PANIC_PERMS = (
    "send_messages",
    "add_reactions",
    "create_public_threads",
    "create_private_threads",
    "send_messages_in_threads",
)

# Permissions considered dangerous when granted to a role / @everyone.
DANGEROUS_PERMISSIONS = (
    "administrator",
    "manage_guild",
    "manage_webhooks",
    "manage_roles",
    "manage_channels",
    "ban_members",
    "kick_members",
    "manage_messages",
    "mention_everyone",
    "moderate_members",
)

# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("security-bot")

# --------------------------------------------------------------------------- #
# Bot
# --------------------------------------------------------------------------- #


class SecurityBot(commands.Bot):
    def __init__(self) -> None:
        intents = discord.Intents.default()
        intents.members = True  # needed to resolve/ban members reliably
        super().__init__(command_prefix="!", intents=intents)

    async def setup_hook(self) -> None:
        # Sync slash commands. Guild-scoped sync is instant; global is slow.
        if DEV_GUILD_ID:
            guild = discord.Object(id=DEV_GUILD_ID)
            self.tree.copy_global_to(guild=guild)
            await self.tree.sync(guild=guild)
            log.info("Synced commands to dev guild %s", DEV_GUILD_ID)
        else:
            await self.tree.sync()
            log.info("Synced commands globally")

    async def on_ready(self) -> None:
        log.info("Logged in as %s (ID: %s)", self.user, self.user.id)
        log.info("Serving %d guild(s)", len(self.guilds))


bot = SecurityBot()


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


async def get_mod_log_channel(guild: discord.Guild) -> Optional[discord.TextChannel]:
    """Resolve the mod-log channel by configured ID, then by name `mod-logs`."""
    channel: Optional[discord.abc.GuildChannel] = None
    if MOD_LOG_CHANNEL_ID:
        channel = guild.get_channel(MOD_LOG_CHANNEL_ID)
    if channel is None:
        channel = discord.utils.get(guild.text_channels, name="mod-logs")
    return channel if isinstance(channel, discord.TextChannel) else None


async def send_mod_log(guild: discord.Guild, embed: discord.Embed) -> None:
    """Best-effort log to the mod-log channel. Never raises."""
    channel = await get_mod_log_channel(guild)
    if channel is None:
        log.warning("No mod-log channel found for guild %s", guild.id)
        return
    try:
        await channel.send(embed=embed)
    except discord.HTTPException as exc:
        log.warning("Failed to write to mod-log channel: %s", exc)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def load_panic_state() -> dict:
    """Load the panic-lock state file. Returns {} if missing or corrupt."""
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    except OSError as exc:
        log.warning("Could not read panic state: %s", exc)
        return {}


def save_panic_state(state: dict) -> None:
    """Persist the panic-lock state file (best effort)."""
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2)
    except OSError as exc:
        log.warning("Could not write panic state: %s", exc)


# --------------------------------------------------------------------------- #
# Feature 1: Bulk purge a user + ban
# --------------------------------------------------------------------------- #


@bot.tree.command(
    name="bulk-purge-user",
    description="Ban a user and delete their messages from the last 14 days.",
)
@app_commands.describe(user="The user to ban and purge (mention or ID).")
@app_commands.default_permissions(administrator=True)
@app_commands.checks.has_permissions(administrator=True)
async def bulk_purge_user(interaction: discord.Interaction, user: discord.User) -> None:
    guild = interaction.guild
    if guild is None:
        await interaction.response.send_message(
            "This command can only be used in a server.", ephemeral=True
        )
        return

    # Scanning every channel can take a while -> defer immediately.
    await interaction.response.defer(thinking=True)

    # 1. Ban first so the user can't keep posting while we clean up.
    #    delete_message_seconds also clears very recent messages server-side.
    try:
        await guild.ban(
            user,
            reason=f"bulk-purge-user by {interaction.user} ({interaction.user.id})",
            delete_message_seconds=0,  # we handle deletion ourselves via purge
        )
    except discord.Forbidden:
        await interaction.followup.send(
            "❌ I lack permission to ban this user. Check my role position and "
            "`Ban Members` permission.",
        )
        return
    except discord.HTTPException as exc:
        await interaction.followup.send(f"❌ Failed to ban user: {exc}")
        return

    # 2. Find and remove webhooks created by the target. Malicious apps spam via
    #    webhooks, whose messages have a webhook author (not a user), so deleting
    #    the webhook also lets us catch its messages by webhook_id below. Scoped
    #    to webhooks this user created so legitimate integrations are untouched.
    target_webhook_ids: set[int] = set()
    deleted_webhooks = 0
    try:
        for wh in await guild.webhooks():
            creator = getattr(wh, "user", None)
            if creator is not None and creator.id == user.id:
                target_webhook_ids.add(wh.id)
                try:
                    await wh.delete(reason=f"bulk-purge-user: {user} ({user.id})")
                    deleted_webhooks += 1
                except discord.HTTPException as exc:
                    log.warning("Failed to delete webhook %s: %s", wh.id, exc)
    except discord.Forbidden:
        log.info("No Manage Webhooks permission; skipping webhook cleanup.")
    except discord.HTTPException as exc:
        log.warning("Failed to enumerate webhooks: %s", exc)

    # 3/4. Purge messages newer than 14 days across all text channels & threads.
    cutoff = utcnow() - BULK_DELETE_MAX_AGE

    def is_target(message: discord.Message) -> bool:
        # Match the user's own messages OR messages posted by their webhooks.
        if message.author.id == user.id:
            return True
        return message.webhook_id is not None and message.webhook_id in target_webhook_ids

    total_deleted = 0
    skipped_channels = 0

    # Collect text channels plus their threads (active + archived).
    targets: list[discord.abc.Messageable] = list(guild.text_channels)
    for ch in guild.text_channels:
        targets.extend(ch.threads)

    for channel in targets:
        # Skip channels we can't read/manage messages in.
        perms = channel.permissions_for(guild.me)
        if not (perms.read_message_history and perms.manage_messages):
            skipped_channels += 1
            continue
        try:
            # `after=cutoff` ensures we never touch messages older than 14 days,
            # which keeps us on the fast bulk-delete path and avoids rate limits.
            deleted = await channel.purge(
                limit=None,
                check=is_target,
                after=cutoff,
                bulk=True,
                reason=f"bulk-purge-user: {user} ({user.id})",
            )
            total_deleted += len(deleted)
        except discord.Forbidden:
            skipped_channels += 1
        except discord.HTTPException as exc:
            log.warning("Purge failed in #%s: %s", getattr(channel, "name", channel), exc)
            skipped_channels += 1

    # 5. Summary.
    summary = (
        f"🔨 Banned **{user}** (`{user.id}`) and deleted **{total_deleted}** "
        f"message(s) from the last 14 days."
    )
    if deleted_webhooks:
        summary += f"\n🧹 Removed **{deleted_webhooks}** webhook(s) created by this user."
    if skipped_channels:
        summary += f"\n⚠️ Skipped {skipped_channels} channel(s) due to missing permissions."
    await interaction.followup.send(summary)

    embed = discord.Embed(
        title="Bulk Purge + Ban",
        description=f"Target: {user.mention} (`{user.id}`)",
        color=discord.Color.red(),
        timestamp=utcnow(),
    )
    embed.add_field(name="Messages deleted", value=str(total_deleted))
    embed.add_field(name="Webhooks removed", value=str(deleted_webhooks))
    embed.add_field(name="Channels skipped", value=str(skipped_channels))
    embed.set_footer(text=f"Action by {interaction.user}")
    await send_mod_log(guild, embed)


# --------------------------------------------------------------------------- #
# Feature 2: Permission & risk audit
# --------------------------------------------------------------------------- #


@bot.tree.command(
    name="audit-permissions",
    description="Audit roles, @everyone, and integrations for dangerous permissions.",
)
@app_commands.default_permissions(administrator=True)
@app_commands.checks.has_permissions(administrator=True)
async def audit_permissions(interaction: discord.Interaction) -> None:
    guild = interaction.guild
    if guild is None:
        await interaction.response.send_message(
            "This command can only be used in a server.", ephemeral=True
        )
        return

    await interaction.response.defer(thinking=True)

    risky_roles: list[str] = []
    everyone_risks: list[str] = []

    for role in guild.roles:
        granted = [
            perm
            for perm, value in role.permissions
            if value and perm in DANGEROUS_PERMISSIONS
        ]
        if not granted:
            continue
        pretty = ", ".join(p.replace("_", " ").title() for p in granted)
        if role.is_default():  # @everyone
            everyone_risks.append(pretty)
        else:
            member_count = len(role.members)
            risky_roles.append(
                f"**{role.name}** ({member_count} member(s)): {pretty}"
            )

    # Integrations (bots, webhooks-as-integrations, app installs).
    integration_lines: list[str] = []
    try:
        integrations = await guild.integrations()
        for integ in integrations:
            account = getattr(integ, "account", None)
            account_name = getattr(account, "name", "unknown")
            # Flag bot/application integrations that carry their own role.
            flagged = ""
            role_obj = getattr(integ, "role", None)
            if role_obj is not None:
                role_perms = [
                    p.replace("_", " ").title()
                    for p, v in role_obj.permissions
                    if v and p in DANGEROUS_PERMISSIONS
                ]
                if role_perms:
                    flagged = f" ⚠️ {', '.join(role_perms)}"
            integration_lines.append(
                f"• **{integ.name}** ({integ.type}) — account: {account_name}{flagged}"
            )
    except discord.Forbidden:
        integration_lines.append("_Missing permission to read integrations._")
    except discord.HTTPException as exc:
        integration_lines.append(f"_Failed to fetch integrations: {exc}_")

    # Build a color-coded embed: red if any critical risk, green otherwise.
    critical = bool(everyone_risks) or bool(risky_roles)
    embed = discord.Embed(
        title=f"🔐 Permission & Risk Audit — {guild.name}",
        color=discord.Color.red() if critical else discord.Color.green(),
        timestamp=utcnow(),
    )

    if everyone_risks:
        embed.add_field(
            name="🚨 @everyone has dangerous permissions",
            value="\n".join(f"`{r}`" for r in everyone_risks),
            inline=False,
        )
    else:
        embed.add_field(
            name="✅ @everyone",
            value="No dangerous permissions granted.",
            inline=False,
        )

    if risky_roles:
        # Discord field values cap at 1024 chars; chunk if needed.
        chunk = ""
        idx = 1
        for line in risky_roles:
            if len(chunk) + len(line) + 1 > 1000:
                embed.add_field(
                    name=f"⚠️ Roles with dangerous permissions ({idx})",
                    value=chunk or "—",
                    inline=False,
                )
                chunk = ""
                idx += 1
            chunk += line + "\n"
        if chunk:
            embed.add_field(
                name=f"⚠️ Roles with dangerous permissions ({idx})",
                value=chunk,
                inline=False,
            )
    else:
        embed.add_field(
            name="✅ Roles",
            value="No non-default roles hold dangerous permissions.",
            inline=False,
        )

    integ_value = "\n".join(integration_lines) if integration_lines else "None found."
    if len(integ_value) > 1024:
        integ_value = integ_value[:1000] + "\n… (truncated)"
    embed.add_field(name="🔌 Integrations & Apps", value=integ_value, inline=False)

    embed.set_footer(text=f"Requested by {interaction.user}")
    await interaction.followup.send(embed=embed)
    await send_mod_log(guild, embed)


# --------------------------------------------------------------------------- #
# Feature 3: Webhook purge
# --------------------------------------------------------------------------- #


@bot.tree.command(
    name="purge-webhooks",
    description="Delete every webhook in the server to close spam backdoors.",
)
@app_commands.default_permissions(administrator=True)
@app_commands.checks.has_permissions(administrator=True)
async def purge_webhooks(interaction: discord.Interaction) -> None:
    guild = interaction.guild
    if guild is None:
        await interaction.response.send_message(
            "This command can only be used in a server.", ephemeral=True
        )
        return

    await interaction.response.defer(thinking=True)

    deleted_names: list[str] = []
    failed = 0

    # guild.webhooks() returns webhooks across all channels in one call.
    try:
        webhooks = await guild.webhooks()
    except discord.Forbidden:
        await interaction.followup.send(
            "❌ I need the `Manage Webhooks` permission to do this."
        )
        return

    for wh in webhooks:
        channel_name = getattr(wh.channel, "name", "unknown")
        try:
            await wh.delete(reason=f"purge-webhooks by {interaction.user}")
            deleted_names.append(f"{wh.name} (#{channel_name})")
        except discord.HTTPException as exc:
            log.warning("Failed to delete webhook %s: %s", wh.name, exc)
            failed += 1

    msg = f"🧹 Deleted **{len(deleted_names)}** webhook(s)."
    if failed:
        msg += f" Failed to delete {failed}."
    await interaction.followup.send(msg)

    embed = discord.Embed(
        title="Webhook Purge",
        color=discord.Color.orange(),
        timestamp=utcnow(),
        description=(
            "\n".join(f"• {n}" for n in deleted_names)
            if deleted_names
            else "No webhooks found."
        )[:4000],
    )
    embed.add_field(name="Deleted", value=str(len(deleted_names)))
    embed.add_field(name="Failed", value=str(failed))
    embed.set_footer(text=f"Action by {interaction.user}")
    await send_mod_log(guild, embed)


# --------------------------------------------------------------------------- #
# Feature 4: Panic button (lock / unlock)
# --------------------------------------------------------------------------- #


@bot.tree.command(
    name="panic",
    description="Lock down or restore all text channels during a raid.",
)
@app_commands.describe(action="Whether to lock the server down or unlock it.")
@app_commands.choices(
    action=[
        app_commands.Choice(name="lock", value="lock"),
        app_commands.Choice(name="unlock", value="unlock"),
    ]
)
@app_commands.default_permissions(administrator=True)
@app_commands.checks.has_permissions(administrator=True)
async def panic(
    interaction: discord.Interaction, action: app_commands.Choice[str]
) -> None:
    guild = interaction.guild
    if guild is None:
        await interaction.response.send_message(
            "This command can only be used in a server.", ephemeral=True
        )
        return

    await interaction.response.defer(thinking=True)

    everyone = guild.default_role
    state = load_panic_state()
    gid = str(guild.id)

    if action.value == "lock":
        await _panic_lock(interaction, guild, everyone, state, gid)
    else:
        await _panic_unlock(interaction, guild, everyone, state, gid)


async def _panic_lock(interaction, guild, everyone, state, gid) -> None:
    # Refuse to lock twice — a second lock would overwrite the saved pre-lock
    # state with already-locked values, making a later unlock unable to restore.
    if gid in state:
        await interaction.followup.send(
            "⚠️ This server already has an active panic lock. Run `/panic unlock` "
            "first if you want to re-lock."
        )
        return

    locked: dict[str, dict] = {}
    skipped_readonly: list[str] = []
    failed = 0

    for channel in guild.text_channels:
        perms = channel.permissions_for(guild.me)
        if not perms.manage_roles:
            failed += 1
            continue

        overwrite = channel.overwrites_for(everyone)

        # Already read-only for @everyone? Leave it completely untouched and
        # record it so unlock knows never to open it.
        if overwrite.send_messages is False:
            skipped_readonly.append(str(channel.id))
            continue

        # Snapshot the exact prior values so unlock can restore them precisely.
        prior = {perm: getattr(overwrite, perm) for perm in PANIC_PERMS}

        for perm in PANIC_PERMS:
            setattr(overwrite, perm, False)

        try:
            await channel.set_permissions(
                everyone, overwrite=overwrite, reason=f"panic lock by {interaction.user}"
            )
            locked[str(channel.id)] = prior
        except discord.Forbidden:
            failed += 1
        except discord.HTTPException as exc:
            log.warning("panic lock failed in #%s: %s", channel.name, exc)
            failed += 1

    state[gid] = {
        "locked_at": utcnow().isoformat(),
        "locked_by": str(interaction.user),
        "channels": locked,
        "skipped_readonly": skipped_readonly,
    }
    save_panic_state(state)

    msg = f"🔒 Locked **{len(locked)}** text channel(s)."
    if skipped_readonly:
        msg += (
            f"\nℹ️ Left **{len(skipped_readonly)}** already read-only channel(s) "
            f"untouched (they won't be opened on unlock)."
        )
    if failed:
        msg += f"\n⚠️ {failed} channel(s) could not be updated (check my permissions)."
    await interaction.followup.send(msg)

    embed = discord.Embed(
        title="Panic Button — LOCK",
        color=discord.Color.red(),
        timestamp=utcnow(),
    )
    embed.add_field(name="Channels locked", value=str(len(locked)))
    embed.add_field(name="Read-only skipped", value=str(len(skipped_readonly)))
    embed.add_field(name="Failed", value=str(failed))
    embed.set_footer(text=f"Action by {interaction.user}")
    await send_mod_log(guild, embed)


async def _panic_unlock(interaction, guild, everyone, state, gid) -> None:
    saved = state.get(gid)
    if not saved:
        await interaction.followup.send(
            "ℹ️ No active panic lock recorded for this server, so there's nothing "
            "to restore. (If you locked before this version was deployed, adjust the "
            "affected channels manually to avoid disturbing read-only channels.)"
        )
        return

    restored = 0
    failed = 0

    for channel_id, prior in saved.get("channels", {}).items():
        channel = guild.get_channel(int(channel_id))
        if channel is None:  # channel was deleted while locked
            continue

        overwrite = channel.overwrites_for(everyone)
        # Restore each toggled permission to its EXACT pre-lock value (True/False/None).
        for perm in PANIC_PERMS:
            setattr(overwrite, perm, prior.get(perm))

        try:
            await channel.set_permissions(
                everyone, overwrite=overwrite, reason=f"panic unlock by {interaction.user}"
            )
            restored += 1
        except discord.Forbidden:
            failed += 1
        except discord.HTTPException as exc:
            log.warning("panic unlock failed in #%s: %s", channel.name, exc)
            failed += 1

    skipped = len(saved.get("skipped_readonly", []))

    # Clear the lock state for this guild.
    state.pop(gid, None)
    save_panic_state(state)

    msg = f"🔓 Restored **{restored}** channel(s) to their pre-lock state."
    if skipped:
        msg += f"\nℹ️ {skipped} pre-existing read-only channel(s) were left untouched, as recorded."
    if failed:
        msg += f"\n⚠️ {failed} channel(s) could not be updated (check my permissions)."
    await interaction.followup.send(msg)

    embed = discord.Embed(
        title="Panic Button — UNLOCK",
        color=discord.Color.green(),
        timestamp=utcnow(),
    )
    embed.add_field(name="Channels restored", value=str(restored))
    embed.add_field(name="Read-only left as-is", value=str(skipped))
    embed.add_field(name="Failed", value=str(failed))
    embed.set_footer(text=f"Action by {interaction.user}")
    await send_mod_log(guild, embed)


# --------------------------------------------------------------------------- #
# Feature 5: Wipe invites
# --------------------------------------------------------------------------- #


@bot.tree.command(
    name="wipe-invites",
    description="Delete all active invite links to stop banned users returning.",
)
@app_commands.default_permissions(administrator=True)
@app_commands.checks.has_permissions(administrator=True)
async def wipe_invites(interaction: discord.Interaction) -> None:
    guild = interaction.guild
    if guild is None:
        await interaction.response.send_message(
            "This command can only be used in a server.", ephemeral=True
        )
        return

    await interaction.response.defer(thinking=True)

    try:
        invites = await guild.invites()
    except discord.Forbidden:
        await interaction.followup.send(
            "❌ I need the `Manage Server` permission to read invites."
        )
        return

    deleted = 0
    failed = 0
    for invite in invites:
        try:
            await invite.delete(reason=f"wipe-invites by {interaction.user}")
            deleted += 1
        except discord.HTTPException as exc:
            log.warning("Failed to delete invite %s: %s", invite.code, exc)
            failed += 1

    msg = (
        f"🧨 Deleted **{deleted}** invite link(s). "
        f"New invites must be generated manually."
    )
    if failed:
        msg += f" ⚠️ Failed to delete {failed}."
    await interaction.followup.send(msg)

    embed = discord.Embed(
        title="Invite Wipe",
        description=(
            f"All active invites have been revoked by {interaction.user.mention}. "
            f"Moderators must create new invites as needed."
        ),
        color=discord.Color.orange(),
        timestamp=utcnow(),
    )
    embed.add_field(name="Deleted", value=str(deleted))
    embed.add_field(name="Failed", value=str(failed))
    embed.set_footer(text=f"Action by {interaction.user}")
    await send_mod_log(guild, embed)


# --------------------------------------------------------------------------- #
# Feature 6: Trace an app/bot back to the human behind it
# --------------------------------------------------------------------------- #


@bot.tree.command(
    name="trace-app",
    description="Find the user(s) behind an app/bot (e.g. one spamming) so you can ban them too.",
)
@app_commands.describe(
    app="The app/bot to trace (mention or ID).",
    scan_messages="Scan recent messages to find who invoked a user-installed app (default: on).",
)
@app_commands.default_permissions(administrator=True)
@app_commands.checks.has_permissions(administrator=True)
async def trace_app(
    interaction: discord.Interaction,
    app: discord.User,
    scan_messages: bool = True,
) -> None:
    guild = interaction.guild
    if guild is None:
        await interaction.response.send_message(
            "This command can only be used in a server.", ephemeral=True
        )
        return

    await interaction.response.defer(thinking=True)

    # user_id -> {"reasons": set[str], "messages": int}
    candidates: dict[int, dict] = {}

    def note(user: discord.abc.User | None, reason: str, msgs: int = 0) -> None:
        if user is None or user.bot:
            return
        entry = candidates.setdefault(user.id, {"obj": user, "reasons": set(), "messages": 0})
        entry["reasons"].add(reason)
        entry["messages"] += msgs

    # 1. Integrations: integration.user is the human who installed the app/bot.
    try:
        for integ in await guild.integrations():
            acct = getattr(integ, "account", None)
            appobj = getattr(integ, "application", None)
            matches = (
                (appobj is not None and getattr(appobj, "id", None) == app.id)
                or (acct is not None and str(getattr(acct, "id", "")) == str(app.id))
                or (integ.name and integ.name.lower() == app.name.lower())
            )
            if matches:
                note(getattr(integ, "user", None), "installed the integration")
    except discord.Forbidden:
        pass
    except discord.HTTPException as exc:
        log.warning("trace-app: integrations fetch failed: %s", exc)

    # 2. Scan recent messages from this app. User-installed apps post via an
    #    interaction; message.interaction_metadata.user is the human who triggered it.
    scanned_channels = 0
    if scan_messages:
        cutoff = utcnow() - BULK_DELETE_MAX_AGE
        targets: list = list(guild.text_channels)
        for ch in guild.text_channels:
            targets.extend(ch.threads)

        for channel in targets:
            perms = channel.permissions_for(guild.me)
            if not perms.read_message_history:
                continue
            scanned_channels += 1
            try:
                async for msg in channel.history(limit=500, after=cutoff):
                    if msg.author.id != app.id:
                        continue
                    meta = getattr(msg, "interaction_metadata", None)
                    invoker = getattr(meta, "user", None) if meta else None
                    if invoker is not None:
                        note(invoker, "invoked the app to post", msgs=1)
            except (discord.Forbidden, discord.HTTPException):
                continue

    # Build the report.
    if not candidates:
        await interaction.followup.send(
            f"🔍 Couldn't link **{app}** (`{app.id}`) to a specific user.\n"
            "• If it's a classic bot, check **Server Settings → Integrations** for who added it.\n"
            "• User-installed apps only reveal an invoker on messages they posted via an "
            "interaction — try again with `scan_messages` on, or after it posts again."
        )
        return

    embed = discord.Embed(
        title=f"🔍 Trace results for {app}",
        description=(
            f"App ID: `{app.id}`\nReview before acting, then ban a confirmed culprit "
            f"with `/bulk-purge-user`."
        ),
        color=discord.Color.orange(),
        timestamp=utcnow(),
    )
    # Most message-spam first.
    for uid, data in sorted(candidates.items(), key=lambda kv: kv[1]["messages"], reverse=True):
        user = data["obj"]
        reasons = ", ".join(sorted(data["reasons"]))
        extra = f" — {data['messages']} message(s)" if data["messages"] else ""
        embed.add_field(
            name=f"{user} (`{uid}`)",
            value=f"{reasons}{extra}",
            inline=False,
        )
    embed.set_footer(text=f"Scanned {scanned_channels} channel(s) • by {interaction.user}")
    await interaction.followup.send(embed=embed)
    await send_mod_log(guild, embed)


# --------------------------------------------------------------------------- #
# Global error handler for slash commands
# --------------------------------------------------------------------------- #


@bot.tree.error
async def on_app_command_error(
    interaction: discord.Interaction, error: app_commands.AppCommandError
) -> None:
    if isinstance(error, app_commands.MissingPermissions):
        message = "⛔ You need the **Administrator** permission to use this command."
    elif isinstance(error, app_commands.BotMissingPermissions):
        missing = ", ".join(error.missing_permissions)
        message = f"⚠️ I'm missing required permissions: {missing}"
    elif isinstance(error, app_commands.CommandOnCooldown):
        message = f"⏳ This command is on cooldown. Try again in {error.retry_after:.0f}s."
    else:
        log.exception("Unhandled command error", exc_info=error)
        message = f"❌ An unexpected error occurred: {error}"

    # Respond whether or not we've already deferred.
    try:
        if interaction.response.is_done():
            await interaction.followup.send(message, ephemeral=True)
        else:
            await interaction.response.send_message(message, ephemeral=True)
    except discord.HTTPException:
        pass


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def main() -> None:
    if not BOT_TOKEN:
        raise SystemExit(
            "BOT_TOKEN is not set. Copy .env.example to .env and add your token."
        )
    bot.run(BOT_TOKEN, log_handler=None)  # we configured logging ourselves


if __name__ == "__main__":
    main()
