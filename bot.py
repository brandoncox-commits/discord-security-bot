"""
Bams Modmin Tools
=================

A Discord moderation & security bot focused on incident response and server
hardening. Built on discord.py 2.x using slash (application) commands.

Commands
-----------------------------------------------------------------------------
Admin-only (require the Administrator permission, hidden from regular members):
/help                        Show the command list.
/bulk-purge-user <user>      Ban a user, delete their last-14-day messages, and
                             remove webhooks they created (plus those messages).
/audit-permissions           Audit roles, @everyone, and integrations for risk.
/purge-webhooks              Delete every webhook in the server.
/panic <lock|unlock>         Freeze / restore all text channels during a raid.
/wipe-invites                Delete all active invite links.
/trace-app <app>             Find the user(s) behind an app/bot.
/xp-config                   Configure the per-guild XP/leveling system.

Open to all members:
/rank [user]                 Show a member's level, XP, and server rank.
/leaderboard                 Show the top 10 members by XP in this server.

Setup
-----
1. Copy `.env.example` to `.env` and fill in the values.
2. pip install -r requirements.txt
3. python bot.py

Install scope: `bot applications.commands`. Required privileged intent:
Server Members Intent (enable in the Developer Portal).
"""

from __future__ import annotations

import json
import logging
import os
import random
from datetime import datetime, timedelta, timezone
from typing import Optional

import aiosqlite
import discord
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
# Optional fixed mod-log channel ID. For a public bot this is usually blank and
# the bot logs to a channel named "mod-logs" in whichever server ran the command.
MOD_LOG_CHANNEL_ID = int(os.getenv("MOD_LOG_CHANNEL_ID", "0") or "0")
# Optional: a guild ID to sync commands to instantly (handy for testing). Leave
# blank for global sync (available everywhere, but can take up to ~1h the first time).
DEV_GUILD_ID = int(os.getenv("DEV_GUILD_ID", "0") or "0")

# Discord only allows *bulk* deletion of messages younger than 14 days.
BULK_DELETE_MAX_AGE = timedelta(days=14)

# Persisted panic-lock state lives next to this file, keyed by guild ID, so that
# /panic unlock can restore each channel to its EXACT pre-lock overwrite values.
STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "panic_state.json")

# XP database lives beside this file. Listed in .gitignore.
XP_DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "xp.db")

# The @everyone overwrites that /panic toggles.
PANIC_PERMS = (
    "send_messages",
    "add_reactions",
    "create_public_threads",
    "create_private_threads",
    "send_messages_in_threads",
)

# --- Permission risk model -------------------------------------------------- #
# Tiered model based on a Discord permission risk breakdown plus Discord's own
# guidance (sources listed in the README). Danger tiers, most to least severe.
RISK_CRITICAL = "Critical"
RISK_EXTREME = "Extreme"
RISK_HIGH = "High"
RISK_MEDIUM = "Medium"
RISK_LOW = "Low"

RISK_ORDER = {RISK_CRITICAL: 4, RISK_EXTREME: 3, RISK_HIGH: 2, RISK_MEDIUM: 1, RISK_LOW: 0}
RISK_EMOJI = {
    RISK_CRITICAL: "🟣",
    RISK_EXTREME: "🔴",
    RISK_HIGH: "🟠",
    RISK_MEDIUM: "🟡",
    RISK_LOW: "⚪",
}

# Friendly names matching Discord's UI where it differs from the API flag.
PERM_DISPLAY = {
    "manage_guild": "Manage Server",
    "moderate_members": "Timeout Members",
    "use_external_apps": "Use External Apps",
    "mention_everyone": "Mention @everyone / @here",
    "manage_expressions": "Manage Expressions (emoji/stickers)",
    "create_expressions": "Create Expressions",
    "create_instant_invite": "Create Invite",
}

# flag -> (risk tier, why it's risky / abuse potential, recommended placement)
PERMISSION_RISK: dict[str, tuple[str, str, str]] = {
    "administrator": (
        RISK_CRITICAL,
        "Grants every permission and bypasses all channel/role overrides. One "
        "compromised holder can delete channels, ban everyone, or add malicious bots.",
        "Server owner only",
    ),
    "manage_guild": (
        RISK_EXTREME,
        "Can add bots/apps and change server & AutoMod settings — used to plant a "
        "nuke bot or strip moderation rules.",
        "Admin",
    ),
    "manage_roles": (
        RISK_EXTREME,
        "Can edit/delete lower roles and grant dangerous permissions to others — a "
        "direct privilege-escalation path.",
        "Admin",
    ),
    "manage_channels": (
        RISK_EXTREME,
        "Can delete every channel and category — irreversible.",
        "Admin",
    ),
    "manage_webhooks": (
        RISK_EXTREME,
        "Webhooks bypass AutoMod and can spam @everyone pings and scam links — a "
        "prime raid/scam vector that persists after an app is removed.",
        "Admin",
    ),
    "ban_members": (
        RISK_HIGH,
        "Can maliciously remove (and bar the return of) key members.",
        "Admin",
    ),
    "kick_members": (
        RISK_HIGH,
        "Can disrupt the community or mass-remove members via Prune.",
        "Moderator / Admin",
    ),
    "mention_everyone": (
        RISK_HIGH,
        "Can ping the whole server — the core tool of mention raids.",
        "Admin",
    ),
    "manage_messages": (
        RISK_HIGH,
        "Can delete others' messages and wipe channel history — irreversible, and can "
        "silently censor users.",
        "Moderator / Admin",
    ),
    "use_external_apps": (
        RISK_HIGH,
        "Lets members invoke user-installed apps in the server — the vector behind "
        "user-app spam (e.g. gore-image apps). High risk on @everyone.",
        "Restrict on @everyone",
    ),
    "moderate_members": (
        RISK_MEDIUM,
        "Timeout members — a core mod tool, but can be abused to silence users.",
        "Moderator / Admin",
    ),
    "manage_threads": (
        RISK_MEDIUM,
        "Can delete or lock other members' threads.",
        "Moderator / Admin",
    ),
    "manage_nicknames": (
        RISK_MEDIUM,
        "Can rename members — used for harassment or impersonation.",
        "Moderator / Admin",
    ),
    "manage_events": (
        RISK_LOW,
        "Can edit/delete scheduled server events.",
        "Moderator / Admin",
    ),
    "manage_expressions": (
        RISK_LOW,
        "Can add/remove emojis, stickers, and soundboard sounds.",
        "Moderator / Admin",
    ),
}


def perm_name(flag: str) -> str:
    """Human-friendly permission name matching Discord's UI."""
    return PERM_DISPLAY.get(flag, flag.replace("_", " ").title())


def assess_permissions(permissions: discord.Permissions) -> list[tuple[str, str, str, str]]:
    """Return (flag, risk, why, recommended) for risky perms present, worst first."""
    found: list[tuple[str, str, str, str]] = []
    for flag, value in permissions:
        if value and flag in PERMISSION_RISK:
            risk, why, rec = PERMISSION_RISK[flag]
            found.append((flag, risk, why, rec))
    found.sort(key=lambda f: RISK_ORDER[f[1]], reverse=True)
    return found


# --------------------------------------------------------------------------- #
# XP / Leveling — math helpers
# --------------------------------------------------------------------------- #
# MEE6-style cumulative XP curve.
#   XP required to advance FROM level n TO n+1 = 5*(n**2) + 50*n + 100
#   e.g. level 0→1 = 100 XP, 1→2 = 155 XP, 2→3 = 220 XP, ...
#
# xp_for_level(n)  — cumulative XP a user needs to *be* at level n (i.e. reach it)
# level_for_xp(xp) — the level a user is at given their cumulative XP total


def xp_for_level(level: int) -> int:
    """Return the cumulative XP required to reach `level` from level 0.

    Uses the MEE6 formula: each step n→n+1 costs 5*(n**2) + 50*n + 100.
    xp_for_level(0) == 0, xp_for_level(1) == 100, xp_for_level(2) == 255, ...
    """
    total = 0
    for n in range(level):
        total += 5 * (n ** 2) + 50 * n + 100
    return total


def level_for_xp(total_xp: int) -> int:
    """Return the level a user is at given their cumulative XP total.

    Walks up levels until the next level would require more XP than the user has.
    """
    level = 0
    while True:
        # XP needed to advance from current level to the next
        next_step = 5 * (level ** 2) + 50 * level + 100
        if total_xp < xp_for_level(level + 1):
            return level
        level += 1
        # Safety cap — no one reaches level 1000 in practice
        if level >= 1000:
            return level


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("modmin-tools")

# --------------------------------------------------------------------------- #
# Bot
# --------------------------------------------------------------------------- #


class ModminBot(commands.Bot):
    def __init__(self) -> None:
        intents = discord.Intents.default()
        intents.members = True  # needed for accurate role member counts & bans
        super().__init__(command_prefix="!", intents=intents, help_command=None)
        # Shared aiosqlite connection; set in setup_hook, closed in close().
        self.db: Optional[aiosqlite.Connection] = None

    async def setup_hook(self) -> None:
        # Open the XP database and ensure tables exist.
        self.db = await aiosqlite.connect(XP_DB_FILE)
        self.db.row_factory = aiosqlite.Row
        await self.db.execute("PRAGMA journal_mode=WAL")
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS user_xp (
                guild_id    INTEGER NOT NULL,
                user_id     INTEGER NOT NULL,
                xp          INTEGER NOT NULL DEFAULT 0,
                level       INTEGER NOT NULL DEFAULT 0,
                last_xp_at  TEXT,
                PRIMARY KEY (guild_id, user_id)
            )
        """)
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS guild_xp_config (
                guild_id           INTEGER PRIMARY KEY,
                enabled            INTEGER NOT NULL DEFAULT 1,
                xp_min             INTEGER NOT NULL DEFAULT 15,
                xp_max             INTEGER NOT NULL DEFAULT 25,
                cooldown_secs      INTEGER NOT NULL DEFAULT 60,
                level_up_channel_id INTEGER
            )
        """)
        await self.db.commit()
        log.info("XP database ready at %s", XP_DB_FILE)

        if DEV_GUILD_ID:
            guild = discord.Object(id=DEV_GUILD_ID)
            self.tree.copy_global_to(guild=guild)
            await self.tree.sync(guild=guild)
            log.info("Synced commands to dev guild %s", DEV_GUILD_ID)
        else:
            await self.tree.sync()
            log.info("Synced commands globally")

    async def close(self) -> None:
        if self.db is not None:
            await self.db.close()
            log.info("XP database connection closed")
        await super().close()

    async def on_ready(self) -> None:
        log.info("Logged in as %s (ID: %s)", self.user, self.user.id)
        log.info("Serving %d guild(s)", len(self.guilds))
        await self.change_presence(
            activity=discord.Activity(type=discord.ActivityType.watching, name="/help")
        )


bot = ModminBot()


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
# XP helpers — DB access
# --------------------------------------------------------------------------- #


async def _get_guild_xp_config(db: aiosqlite.Connection, guild_id: int) -> aiosqlite.Row:
    """Return the guild XP config row, lazily inserting defaults if absent."""
    async with db.execute(
        "SELECT * FROM guild_xp_config WHERE guild_id = ?", (guild_id,)
    ) as cur:
        row = await cur.fetchone()
    if row is None:
        await db.execute(
            "INSERT OR IGNORE INTO guild_xp_config (guild_id) VALUES (?)", (guild_id,)
        )
        await db.commit()
        async with db.execute(
            "SELECT * FROM guild_xp_config WHERE guild_id = ?", (guild_id,)
        ) as cur:
            row = await cur.fetchone()
    return row


async def _get_user_xp_row(
    db: aiosqlite.Connection, guild_id: int, user_id: int
) -> aiosqlite.Row:
    """Return the user_xp row, lazily inserting a zero row if absent."""
    async with db.execute(
        "SELECT * FROM user_xp WHERE guild_id = ? AND user_id = ?", (guild_id, user_id)
    ) as cur:
        row = await cur.fetchone()
    if row is None:
        await db.execute(
            "INSERT OR IGNORE INTO user_xp (guild_id, user_id) VALUES (?, ?)",
            (guild_id, user_id),
        )
        await db.commit()
        async with db.execute(
            "SELECT * FROM user_xp WHERE guild_id = ? AND user_id = ?", (guild_id, user_id)
        ) as cur:
            row = await cur.fetchone()
    return row


# --------------------------------------------------------------------------- #
# on_message — award XP
# --------------------------------------------------------------------------- #


@bot.event
async def on_message(message: discord.Message) -> None:
    """Award XP for messages, respecting per-guild config and per-user cooldown."""
    # Ignore bots (including ourselves) and DMs.
    if message.author.bot or message.guild is None:
        return

    db = bot.db
    if db is None:
        return  # DB not yet ready (startup race guard)

    guild_id = message.guild.id
    user_id = message.author.id

    try:
        config = await _get_guild_xp_config(db, guild_id)
        if not config["enabled"]:
            return

        xp_min: int = config["xp_min"]
        xp_max: int = config["xp_max"]
        cooldown_secs: int = config["cooldown_secs"]
        level_up_channel_id: Optional[int] = config["level_up_channel_id"]

        # Cooldown check — compare UTC timestamps stored as ISO-8601 strings.
        row = await _get_user_xp_row(db, guild_id, user_id)
        if row["last_xp_at"] is not None:
            last = datetime.fromisoformat(row["last_xp_at"])
            if (utcnow() - last).total_seconds() < cooldown_secs:
                return  # still on cooldown

        # Award XP.
        gained = random.randint(xp_min, xp_max)
        new_xp = row["xp"] + gained
        old_level = row["level"]
        new_level = level_for_xp(new_xp)
        now_iso = utcnow().isoformat()

        await db.execute(
            """
            INSERT INTO user_xp (guild_id, user_id, xp, level, last_xp_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(guild_id, user_id) DO UPDATE SET
                xp         = excluded.xp,
                level      = excluded.level,
                last_xp_at = excluded.last_xp_at
            """,
            (guild_id, user_id, new_xp, new_level, now_iso),
        )
        await db.commit()

        # Level-up announcement (public, best-effort).
        if new_level > old_level:
            await _announce_level_up(message, new_level, level_up_channel_id)

    except Exception as exc:
        log.warning("XP award failed for user %s in guild %s: %s", user_id, guild_id, exc)


async def _announce_level_up(
    message: discord.Message, new_level: int, level_up_channel_id: Optional[int]
) -> None:
    """Post a public level-up message. Best-effort; swallows all HTTP errors."""
    guild = message.guild
    member = message.author

    # Resolve the destination channel.
    dest: Optional[discord.TextChannel] = None
    if level_up_channel_id:
        ch = guild.get_channel(level_up_channel_id)
        if isinstance(ch, discord.TextChannel):
            dest = ch
    if dest is None:
        # Fall back to the channel where the message was sent.
        if isinstance(message.channel, discord.TextChannel):
            dest = message.channel

    if dest is None:
        return

    # Check bot can send there.
    if not dest.permissions_for(guild.me).send_messages:
        return

    try:
        embed = discord.Embed(
            description=f"🎉 {member.mention} reached **level {new_level}**!",
            color=discord.Color.gold(),
            timestamp=utcnow(),
        )
        if member.display_avatar:
            embed.set_thumbnail(url=member.display_avatar.url)
        embed.set_footer(text=f"{guild.name} XP System")
        await dest.send(embed=embed)
    except discord.HTTPException as exc:
        log.warning("Level-up announcement failed: %s", exc)


# --------------------------------------------------------------------------- #
# /help
# --------------------------------------------------------------------------- #

COMMAND_HELP = [
    ("/help", "Show this command list."),
    (
        "/bulk-purge-user <user>",
        "Ban the user, delete their messages from the last 14 days across all "
        "channels & threads, and remove any webhooks they created (plus those "
        "webhooks' messages).",
    ),
    (
        "/audit-permissions",
        "Audit every role, @everyone, and all integrations/apps for dangerous "
        "permissions. Returns a colour-coded embed.",
    ),
    ("/purge-webhooks", "Delete every webhook in the server to close spam backdoors."),
    (
        "/panic <lock|unlock>",
        "lock freezes all text channels for @everyone (skipping already read-only "
        "ones); unlock restores them to their exact pre-lock state.",
    ),
    ("/wipe-invites", "Delete all active invite links so banned users can't rejoin."),
    (
        "/trace-app <app>",
        "Find the user(s) behind an app/bot — the integration installer and/or "
        "whoever invoked a user-installed app to post — so you can ban them.",
    ),
    (
        "/xp-config",
        "[Admin] Configure the per-guild XP/leveling system: enable/disable, "
        "XP range, cooldown, and level-up announcement channel.",
    ),
    (
        "/rank [user]",
        "[All members] Show a member's current level, XP, XP needed for the next "
        "level, and their rank in the server.",
    ),
    (
        "/leaderboard",
        "[All members] Show the top 10 members by XP in this server.",
    ),
]


@bot.tree.command(name="help", description="Show the list of available commands.")
@app_commands.default_permissions(administrator=True)
@app_commands.checks.has_permissions(administrator=True)
async def help_command(interaction: discord.Interaction) -> None:
    embed = discord.Embed(
        title="🛡️ Bams Modmin Tools — Commands",
        color=discord.Color.blurple(),
        timestamp=utcnow(),
    )
    embed.description = (
        "Most commands require the **Administrator** permission.\n"
        "Commands marked **[All members]** are open to everyone."
    )
    for name, desc in COMMAND_HELP:
        embed.add_field(name=name, value=desc, inline=False)
    embed.set_footer(
        text="Admin actions are logged to #mod-logs if that channel exists. "
        "XP view commands (/rank, /leaderboard) are open to all members."
    )
    await interaction.response.send_message(embed=embed, ephemeral=True)


# --------------------------------------------------------------------------- #
# Feature 1: Bulk purge a user + ban (+ their webhooks)
# --------------------------------------------------------------------------- #


@bot.tree.command(
    name="bulk-purge-user",
    description="Ban a user, delete their last-14-day messages, and remove their webhooks.",
)
@app_commands.describe(user="The user to ban and purge (mention or ID).")
@app_commands.default_permissions(administrator=True)
@app_commands.checks.has_permissions(administrator=True)
@app_commands.checks.bot_has_permissions(ban_members=True, manage_messages=True)
async def bulk_purge_user(interaction: discord.Interaction, user: discord.User) -> None:
    guild = interaction.guild
    if guild is None:
        await interaction.response.send_message(
            "This command can only be used in a server.", ephemeral=True
        )
        return

    await interaction.response.defer(thinking=True, ephemeral=True)

    # 1. Ban first so the user can't keep posting while we clean up.
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
            ephemeral=True,
        )
        return
    except discord.HTTPException as exc:
        await interaction.followup.send(f"❌ Failed to ban user: {exc}", ephemeral=True)
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
        if message.author.id == user.id:
            return True
        return message.webhook_id is not None and message.webhook_id in target_webhook_ids

    total_deleted = 0
    skipped_channels = 0

    targets: list[discord.abc.Messageable] = list(guild.text_channels)
    for ch in guild.text_channels:
        targets.extend(ch.threads)

    for channel in targets:
        perms = channel.permissions_for(guild.me)
        if not (perms.read_message_history and perms.manage_messages):
            skipped_channels += 1
            continue
        try:
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
    await interaction.followup.send(summary, ephemeral=True)

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

    await interaction.response.defer(thinking=True, ephemeral=True)

    # @everyone is the highest-impact surface: every member inherits it.
    everyone_found = assess_permissions(guild.default_role.permissions)

    role_findings: list[tuple[discord.Role, list]] = []
    for role in guild.roles:
        if role.is_default():
            continue
        found = assess_permissions(role.permissions)
        if found:
            role_findings.append((role, found))
    # Worst tier first, then by how many members are affected.
    role_findings.sort(
        key=lambda rf: (max(RISK_ORDER[f[1]] for f in rf[1]), len(rf[0].members)),
        reverse=True,
    )

    # Integrations / apps, flagging any whose managed role carries risky perms.
    integration_lines: list[str] = []
    try:
        for integ in await guild.integrations():
            account = getattr(integ, "account", None)
            account_name = getattr(account, "name", "unknown")
            flagged = ""
            role_obj = getattr(integ, "role", None)
            if role_obj is not None:
                ifound = assess_permissions(role_obj.permissions)
                if ifound:
                    top = ifound[0][1]
                    names = ", ".join(perm_name(f[0]) for f in ifound)
                    flagged = f" {RISK_EMOJI[top]} {names}"
            integration_lines.append(
                f"• **{integ.name}** ({integ.type}) — account: {account_name}{flagged}"
            )
    except discord.Forbidden:
        integration_lines.append("_Missing permission to read integrations._")
    except discord.HTTPException as exc:
        integration_lines.append(f"_Failed to fetch integrations: {exc}_")

    # Tally findings by tier for the summary line.
    tally: dict[str, int] = {}
    for _flag, risk, _why, _rec in everyone_found:
        tally[risk] = tally.get(risk, 0) + 1
    for _role, found in role_findings:
        for _flag, risk, _why, _rec in found:
            tally[risk] = tally.get(risk, 0) + 1

    everyone_max = max((RISK_ORDER[f[1]] for f in everyone_found), default=-1)
    roles_max = max((RISK_ORDER[f[1]] for _r, found in role_findings for f in found), default=-1)
    if everyone_max >= RISK_ORDER[RISK_HIGH] or roles_max >= RISK_ORDER[RISK_EXTREME]:
        color = discord.Color.red()
    elif everyone_found or role_findings:
        color = discord.Color.orange()
    else:
        color = discord.Color.green()

    summary = (
        " · ".join(
            f"{RISK_EMOJI[t]} {tally[t]} {t}"
            for t in (RISK_CRITICAL, RISK_EXTREME, RISK_HIGH, RISK_MEDIUM, RISK_LOW)
            if tally.get(t)
        )
        or "No risky permissions found. ✅"
    )

    embed = discord.Embed(
        title=f"🔐 Permission & Risk Audit — {guild.name}",
        description=f"**Findings:** {summary}",
        color=color,
        timestamp=utcnow(),
    )

    def add_lines_field(title: str, lines: list[str], empty_msg: str) -> None:
        if not lines:
            embed.add_field(name=title, value=empty_msg, inline=False)
            return
        chunk = ""
        name = title
        cont = 1
        for line in lines:
            line = line[:1000]
            if len(chunk) + len(line) + 1 > 1000:
                embed.add_field(name=name, value=chunk, inline=False)
                chunk = ""
                cont += 1
                name = f"{title} (cont. {cont})"
            chunk += line + "\n"
        if chunk:
            embed.add_field(name=name, value=chunk, inline=False)

    everyone_lines = [
        f"{RISK_EMOJI[risk]} **{perm_name(flag)}** ({risk}) — {why}"
        for flag, risk, why, _rec in everyone_found
    ]
    add_lines_field(
        "🚨 @everyone — inherited by EVERY member",
        everyone_lines,
        "✅ No risky permissions granted to @everyone.",
    )

    role_lines = []
    for role, found in role_findings[:40]:
        top = found[0][1]
        perms_str = ", ".join(f"{perm_name(f[0])} {RISK_EMOJI[f[1]]}" for f in found)
        role_lines.append(
            f"{RISK_EMOJI[top]} **{role.name}** ({len(role.members)} member(s)): {perms_str}"
        )
    if len(role_findings) > 40:
        role_lines.append(f"… and {len(role_findings) - 40} more role(s).")
    add_lines_field(
        "⚠️ Roles holding elevated permissions",
        role_lines,
        "✅ No non-default roles hold risky permissions.",
    )

    integ_value = "\n".join(integration_lines) if integration_lines else "None found."
    if len(integ_value) > 1024:
        integ_value = integ_value[:1000] + "\n… (truncated)"
    embed.add_field(name="🔌 Integrations & Apps", value=integ_value, inline=False)

    embed.add_field(
        name="Legend",
        value="🟣 Critical · 🔴 Extreme · 🟠 High · 🟡 Medium · ⚪ Low",
        inline=False,
    )
    embed.set_footer(text=f"Requested by {interaction.user}")
    await interaction.followup.send(embed=embed, ephemeral=True)
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
@app_commands.checks.bot_has_permissions(manage_webhooks=True)
async def purge_webhooks(interaction: discord.Interaction) -> None:
    guild = interaction.guild
    if guild is None:
        await interaction.response.send_message(
            "This command can only be used in a server.", ephemeral=True
        )
        return

    await interaction.response.defer(thinking=True, ephemeral=True)

    deleted_names: list[str] = []
    failed = 0
    try:
        webhooks = await guild.webhooks()
    except discord.Forbidden:
        await interaction.followup.send(
            "❌ I need the `Manage Webhooks` permission to do this.", ephemeral=True
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
    await interaction.followup.send(msg, ephemeral=True)

    embed = discord.Embed(
        title="Webhook Purge",
        color=discord.Color.orange(),
        timestamp=utcnow(),
        description=(
            "\n".join(f"• {n}" for n in deleted_names) if deleted_names else "No webhooks found."
        )[:4000],
    )
    embed.add_field(name="Deleted", value=str(len(deleted_names)))
    embed.add_field(name="Failed", value=str(failed))
    embed.set_footer(text=f"Action by {interaction.user}")
    await send_mod_log(guild, embed)


# --------------------------------------------------------------------------- #
# Feature 4: Panic button (lock / unlock)
# --------------------------------------------------------------------------- #


@bot.tree.command(name="panic", description="Lock down or restore all text channels during a raid.")
@app_commands.describe(action="Whether to lock the server down or unlock it.")
@app_commands.choices(
    action=[
        app_commands.Choice(name="lock", value="lock"),
        app_commands.Choice(name="unlock", value="unlock"),
    ]
)
@app_commands.default_permissions(administrator=True)
@app_commands.checks.has_permissions(administrator=True)
@app_commands.checks.bot_has_permissions(manage_roles=True)
async def panic(interaction: discord.Interaction, action: app_commands.Choice[str]) -> None:
    guild = interaction.guild
    if guild is None:
        await interaction.response.send_message(
            "This command can only be used in a server.", ephemeral=True
        )
        return

    await interaction.response.defer(thinking=True, ephemeral=True)

    everyone = guild.default_role
    state = load_panic_state()
    gid = str(guild.id)

    if action.value == "lock":
        await _panic_lock(interaction, guild, everyone, state, gid)
    else:
        await _panic_unlock(interaction, guild, everyone, state, gid)


async def _panic_lock(interaction, guild, everyone, state, gid) -> None:
    if gid in state:
        await interaction.followup.send(
            "⚠️ This server already has an active panic lock. Run `/panic unlock` "
            "first if you want to re-lock.",
            ephemeral=True,
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
        if overwrite.send_messages is False:
            skipped_readonly.append(str(channel.id))
            continue

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
    await interaction.followup.send(msg, ephemeral=True)

    embed = discord.Embed(title="Panic Button — LOCK", color=discord.Color.red(), timestamp=utcnow())
    embed.add_field(name="Channels locked", value=str(len(locked)))
    embed.add_field(name="Read-only skipped", value=str(len(skipped_readonly)))
    embed.add_field(name="Failed", value=str(failed))
    embed.set_footer(text=f"Action by {interaction.user}")
    await send_mod_log(guild, embed)


async def _panic_unlock(interaction, guild, everyone, state, gid) -> None:
    saved = state.get(gid)
    if not saved:
        await interaction.followup.send(
            "ℹ️ No active panic lock recorded for this server, so there's nothing to restore.",
            ephemeral=True,
        )
        return

    restored = 0
    failed = 0

    for channel_id, prior in saved.get("channels", {}).items():
        channel = guild.get_channel(int(channel_id))
        if channel is None:
            continue
        overwrite = channel.overwrites_for(everyone)
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
    state.pop(gid, None)
    save_panic_state(state)

    msg = f"🔓 Restored **{restored}** channel(s) to their pre-lock state."
    if skipped:
        msg += f"\nℹ️ {skipped} pre-existing read-only channel(s) were left untouched, as recorded."
    if failed:
        msg += f"\n⚠️ {failed} channel(s) could not be updated (check my permissions)."
    await interaction.followup.send(msg, ephemeral=True)

    embed = discord.Embed(title="Panic Button — UNLOCK", color=discord.Color.green(), timestamp=utcnow())
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
@app_commands.checks.bot_has_permissions(manage_guild=True)
async def wipe_invites(interaction: discord.Interaction) -> None:
    guild = interaction.guild
    if guild is None:
        await interaction.response.send_message(
            "This command can only be used in a server.", ephemeral=True
        )
        return

    await interaction.response.defer(thinking=True, ephemeral=True)

    try:
        invites = await guild.invites()
    except discord.Forbidden:
        await interaction.followup.send(
            "❌ I need the `Manage Server` permission to read invites.", ephemeral=True
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

    msg = f"🧨 Deleted **{deleted}** invite link(s). New invites must be generated manually."
    if failed:
        msg += f" ⚠️ Failed to delete {failed}."
    await interaction.followup.send(msg, ephemeral=True)

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
    description="Find the user(s) behind an app/bot so you can ban them too.",
)
@app_commands.describe(
    app="The app/bot to trace (mention or ID).",
    scan_messages="Scan recent messages to find who invoked a user-installed app (default: on).",
)
@app_commands.default_permissions(administrator=True)
@app_commands.checks.has_permissions(administrator=True)
async def trace_app(
    interaction: discord.Interaction, app: discord.User, scan_messages: bool = True
) -> None:
    guild = interaction.guild
    if guild is None:
        await interaction.response.send_message(
            "This command can only be used in a server.", ephemeral=True
        )
        return

    # Ephemeral: trace results can include innocent/unconfirmed user IDs, so only
    # the admin who ran the command should see them (an audit copy still goes to
    # #mod-logs). Deferring ephemerally makes the followups ephemeral too.
    await interaction.response.defer(thinking=True, ephemeral=True)

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
    #    interaction; message.interaction_metadata.user is the human invoker.
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

    if not candidates:
        await interaction.followup.send(
            f"🔍 Couldn't link **{app}** (`{app.id}`) to a specific user.\n"
            "• If it's a classic bot, check **Server Settings → Integrations** for who added it.\n"
            "• User-installed apps only reveal an invoker on messages they posted via an "
            "interaction — try again after it posts.",
            ephemeral=True,
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
    for uid, data in sorted(candidates.items(), key=lambda kv: kv[1]["messages"], reverse=True):
        user = data["obj"]
        reasons = ", ".join(sorted(data["reasons"]))
        extra = f" — {data['messages']} message(s)" if data["messages"] else ""
        embed.add_field(name=f"{user} (`{uid}`)", value=f"{reasons}{extra}", inline=False)
    embed.set_footer(text=f"Scanned {scanned_channels} channel(s) • by {interaction.user}")
    await interaction.followup.send(embed=embed, ephemeral=True)
    await send_mod_log(guild, embed)


# --------------------------------------------------------------------------- #
# Feature 7: XP / Leveling — admin config
# --------------------------------------------------------------------------- #


@bot.tree.command(
    name="xp-config",
    description="View or update the XP/leveling config for this server.",
)
@app_commands.describe(
    enabled="Enable or disable XP earning in this server.",
    xp_min="Minimum XP awarded per message (default 15).",
    xp_max="Maximum XP awarded per message (default 25).",
    cooldown_secs="Seconds between XP awards per user (default 60).",
    level_up_channel="Channel for level-up announcements (leave blank to use the message channel).",
)
@app_commands.default_permissions(administrator=True)
@app_commands.checks.has_permissions(administrator=True)
async def xp_config(
    interaction: discord.Interaction,
    enabled: Optional[bool] = None,
    xp_min: Optional[int] = None,
    xp_max: Optional[int] = None,
    cooldown_secs: Optional[int] = None,
    level_up_channel: Optional[discord.TextChannel] = None,
) -> None:
    guild = interaction.guild
    if guild is None:
        await interaction.response.send_message(
            "This command can only be used in a server.", ephemeral=True
        )
        return

    db = bot.db
    if db is None:
        await interaction.response.send_message(
            "❌ Database is not ready yet. Please try again in a moment.", ephemeral=True
        )
        return

    await interaction.response.defer(thinking=True, ephemeral=True)

    # Load current config (lazy-inserts defaults if needed).
    cfg = await _get_guild_xp_config(db, guild.id)

    # Determine effective values — supplied args override the current config.
    eff_enabled = (1 if enabled else 0) if enabled is not None else cfg["enabled"]
    eff_xp_min = xp_min if xp_min is not None else cfg["xp_min"]
    eff_xp_max = xp_max if xp_max is not None else cfg["xp_max"]
    eff_cooldown = cooldown_secs if cooldown_secs is not None else cfg["cooldown_secs"]
    eff_channel_id = (
        level_up_channel.id if level_up_channel is not None else cfg["level_up_channel_id"]
    )

    # Validate.
    errors: list[str] = []
    if eff_xp_min < 0:
        errors.append("xp_min must be >= 0.")
    if eff_xp_max < 0:
        errors.append("xp_max must be >= 0.")
    if eff_xp_min > eff_xp_max:
        errors.append("xp_min must be <= xp_max.")
    if eff_cooldown < 0:
        errors.append("cooldown_secs must be >= 0.")
    if errors:
        await interaction.followup.send(
            "❌ Invalid configuration:\n" + "\n".join(f"• {e}" for e in errors),
            ephemeral=True,
        )
        return

    # Upsert.
    await db.execute(
        """
        INSERT INTO guild_xp_config
            (guild_id, enabled, xp_min, xp_max, cooldown_secs, level_up_channel_id)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(guild_id) DO UPDATE SET
            enabled             = excluded.enabled,
            xp_min              = excluded.xp_min,
            xp_max              = excluded.xp_max,
            cooldown_secs       = excluded.cooldown_secs,
            level_up_channel_id = excluded.level_up_channel_id
        """,
        (guild.id, eff_enabled, eff_xp_min, eff_xp_max, eff_cooldown, eff_channel_id),
    )
    await db.commit()

    channel_display = (
        f"<#{eff_channel_id}>" if eff_channel_id else "message channel (fallback)"
    )
    embed = discord.Embed(
        title=f"XP Config — {guild.name}",
        color=discord.Color.green() if eff_enabled else discord.Color.greyple(),
        timestamp=utcnow(),
    )
    embed.add_field(name="Enabled", value="Yes" if eff_enabled else "No")
    embed.add_field(name="XP per message", value=f"{eff_xp_min}–{eff_xp_max}")
    embed.add_field(name="Cooldown", value=f"{eff_cooldown}s")
    embed.add_field(name="Level-up channel", value=channel_display, inline=False)
    embed.set_footer(text=f"Updated by {interaction.user}")
    await interaction.followup.send(embed=embed, ephemeral=True)

    # Audit log.
    await send_mod_log(guild, embed)


# --------------------------------------------------------------------------- #
# Feature 7: XP / Leveling — /rank (open to all members)
# --------------------------------------------------------------------------- #


@bot.tree.command(
    name="rank",
    description="Show a member's level, XP, and server rank.",
)
@app_commands.describe(user="The member to look up (default: yourself).")
async def rank(
    interaction: discord.Interaction, user: Optional[discord.Member] = None
) -> None:
    if interaction.guild is None:
        await interaction.response.send_message(
            "This command can only be used in a server.", ephemeral=True
        )
        return

    db = bot.db
    if db is None:
        await interaction.response.send_message(
            "❌ Database is not ready yet. Please try again in a moment.", ephemeral=True
        )
        return

    target = user or interaction.user
    guild = interaction.guild
    guild_id = guild.id
    user_id = target.id

    await interaction.response.defer(thinking=False)  # Public response

    try:
        row = await _get_user_xp_row(db, guild_id, user_id)
        total_xp: int = row["xp"]
        level: int = row["level"]

        # XP progress within the current level.
        xp_at_current = xp_for_level(level)
        xp_at_next = xp_for_level(level + 1)
        xp_into_level = total_xp - xp_at_current
        xp_needed = xp_at_next - xp_at_current

        # Server rank: count users with more XP than this user.
        async with db.execute(
            "SELECT COUNT(*) FROM user_xp WHERE guild_id = ? AND xp > ?",
            (guild_id, total_xp),
        ) as cur:
            above = (await cur.fetchone())[0]
        async with db.execute(
            "SELECT COUNT(*) FROM user_xp WHERE guild_id = ?",
            (guild_id,),
        ) as cur:
            total_members_with_xp = (await cur.fetchone())[0]

        rank_pos = above + 1

        embed = discord.Embed(
            title=f"Rank — {target.display_name}",
            color=target.color if target.color != discord.Color.default() else discord.Color.blurple(),
            timestamp=utcnow(),
        )
        if target.display_avatar:
            embed.set_thumbnail(url=target.display_avatar.url)

        embed.add_field(name="Level", value=str(level))
        embed.add_field(name="Total XP", value=f"{total_xp:,}")
        embed.add_field(name="Server Rank", value=f"#{rank_pos} of {total_members_with_xp}")
        embed.add_field(
            name="Progress to next level",
            value=f"{xp_into_level:,} / {xp_needed:,} XP",
            inline=False,
        )
        embed.set_footer(text=guild.name)

        await interaction.followup.send(embed=embed)

    except Exception as exc:
        log.warning("rank command failed for user %s: %s", user_id, exc)
        await interaction.followup.send(
            "❌ Something went wrong fetching rank data. Please try again.", ephemeral=True
        )


# --------------------------------------------------------------------------- #
# Feature 7: XP / Leveling — /leaderboard (open to all members)
# --------------------------------------------------------------------------- #


@bot.tree.command(
    name="leaderboard",
    description="Show the top 10 members by XP in this server.",
)
async def leaderboard(interaction: discord.Interaction) -> None:
    if interaction.guild is None:
        await interaction.response.send_message(
            "This command can only be used in a server.", ephemeral=True
        )
        return

    db = bot.db
    if db is None:
        await interaction.response.send_message(
            "❌ Database is not ready yet. Please try again in a moment.", ephemeral=True
        )
        return

    guild = interaction.guild

    await interaction.response.defer(thinking=False)  # Public response

    try:
        async with db.execute(
            """
            SELECT user_id, xp, level
            FROM user_xp
            WHERE guild_id = ? AND xp > 0
            ORDER BY xp DESC
            LIMIT 10
            """,
            (guild.id,),
        ) as cur:
            rows = await cur.fetchall()

        if not rows:
            await interaction.followup.send(
                "No XP data yet — members earn XP by chatting!", ephemeral=False
            )
            return

        MEDALS = {1: "🥇", 2: "🥈", 3: "🥉"}
        lines: list[str] = []
        for pos, row in enumerate(rows, start=1):
            medal = MEDALS.get(pos, f"**#{pos}**")
            member = guild.get_member(row["user_id"])
            name = member.display_name if member else f"User {row['user_id']}"
            lines.append(
                f"{medal} **{name}** — Level {row['level']} · {row['xp']:,} XP"
            )

        embed = discord.Embed(
            title=f"🏆 XP Leaderboard — {guild.name}",
            description="\n".join(lines),
            color=discord.Color.gold(),
            timestamp=utcnow(),
        )
        embed.set_footer(text="Earn XP by chatting in the server!")
        await interaction.followup.send(embed=embed)

    except Exception as exc:
        log.warning("leaderboard command failed in guild %s: %s", guild.id, exc)
        await interaction.followup.send(
            "❌ Something went wrong fetching leaderboard data. Please try again.",
            ephemeral=True,
        )


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
        missing = ", ".join(p.replace("_", " ").title() for p in error.missing_permissions)
        message = f"⚠️ I'm missing required permissions: {missing}"
    elif isinstance(error, app_commands.CommandOnCooldown):
        message = f"⏳ This command is on cooldown. Try again in {error.retry_after:.0f}s."
    else:
        log.exception("Unhandled command error", exc_info=error)
        message = f"❌ An unexpected error occurred: {error}"

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
        raise SystemExit("BOT_TOKEN is not set. Copy .env.example to .env and add your token.")
    bot.run(BOT_TOKEN, log_handler=None)


if __name__ == "__main__":
    main()
