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
/twitch-setup <channel>      [Server owner only] Begin the owner-consent handshake
                             to link a Twitch channel. The bot posts a message in
                             that Twitch chat; the channel owner must type
                             !approve-xp there to confirm. Expires in 10 minutes.

Manage Server permission (admins + server owner):
/twitch-notify               Configure go-live card notifications (channel, mention,
                             custom message, go-live background image).
/rank-card-config <url>      Set a custom background image for /rank cards. Once set,
                             /rank renders a 1200x400 card with avatar, level, rank,
                             and XP progress bar. Requires a public HTTPS image URL.

Open to all members:
/rank [user]                 Show a member's level, XP, and server rank.
/leaderboard                 Show the top 10 members by XP in this server.
/twitch-link                 Link your Twitch account to earn XP from Twitch chat
                             (XP is only awarded while the stream is live).
/twitch-unlink               Unlink your Twitch account.

Setup
-----
1. Copy `.env.example` to `.env` and fill in the values.
2. pip install -r requirements.txt
3. python bot.py

Install scope: `bot applications.commands`. Required privileged intent:
Server Members Intent (enable in the Developer Portal).

Twitch integration is OPTIONAL — the bot runs Discord-only if the TWITCH_*
env vars are absent or twitchio is not installed.

Twitch XP (Phase 3)
-------------------
Twitch chat messages earn Discord XP ONLY while the linked stream is live.
Twitch XP is boosted relative to Discord by the per-guild twitch_multiplier
(default 2.0x, configurable via /xp-config).
Live status is determined by polling the Helix Streams API every 60 seconds
(GET /helix/streams?user_id=...) using the existing app access token.
The safe default is OFFLINE: if stream status has not yet been polled or the
broadcaster ID is unknown, no XP is awarded. !link and !approve-xp work
regardless of whether the stream is live.
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import random
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import aiosqlite
import discord
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv

# Card notification modules (optional — Pillow may not be installed yet).
try:
    from image_intake import ingest_image_url, ImageIntakeError
    from card_renderer import render_card, render_rank_card, render_levelup_card
    _CARDS_AVAILABLE = True
except ImportError:
    _CARDS_AVAILABLE = False

# Graceful degradation: twitchio is optional.
try:
    import twitchio
    from twitchio.ext import commands as twitch_commands
    _TWITCHIO_AVAILABLE = True
except ImportError:
    _TWITCHIO_AVAILABLE = False

# aiohttp is needed for the Helix app-token helper (bundled with twitchio / discord.py)
try:
    import aiohttp
    _AIOHTTP_AVAILABLE = True
except ImportError:
    _AIOHTTP_AVAILABLE = False

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

# --- Twitch config (all optional; bot runs Discord-only if any are missing) --- #
TWITCH_CLIENT_ID = os.getenv("TWITCH_CLIENT_ID", "")
TWITCH_CLIENT_SECRET = os.getenv("TWITCH_CLIENT_SECRET", "")
TWITCH_BOT_USERNAME = os.getenv("TWITCH_BOT_USERNAME", "")
TWITCH_BOT_ACCESS_TOKEN = os.getenv("TWITCH_BOT_ACCESS_TOKEN", "")
TWITCH_BOT_REFRESH_TOKEN = os.getenv("TWITCH_BOT_REFRESH_TOKEN", "")

_TWITCH_ENV_VARS = (
    TWITCH_CLIENT_ID,
    TWITCH_CLIENT_SECRET,
    TWITCH_BOT_USERNAME,
    TWITCH_BOT_ACCESS_TOKEN,
    TWITCH_BOT_REFRESH_TOKEN,
)
twitch_enabled: bool = _TWITCHIO_AVAILABLE and all(_TWITCH_ENV_VARS)

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


class _MessageContentIntentFilter(logging.Filter):
    """Drop discord.py's message_content-intent warning.

    This bot uses slash commands only and never reads message text, so the
    "Privileged message content intent is missing" warning is expected and
    harmless. Filtered narrowly by substring so all other warnings survive.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        return "message content intent is missing" not in record.getMessage().lower()


logging.getLogger("discord.ext.commands.bot").addFilter(_MessageContentIntentFilter())

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

        # --- Phase 1 tables ---
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
                level_up_channel_id INTEGER,
                -- Multiplier applied to XP earned from Twitch chat (Discord = 1.0x).
                twitch_multiplier  REAL NOT NULL DEFAULT 2.0
            )
        """)
        # Migration: add twitch_multiplier to guild_xp_config tables created
        # before this column existed. Existing guilds default to a 2.0x boost.
        async with self.db.execute("PRAGMA table_info(guild_xp_config)") as cur:
            cols = {row["name"] for row in await cur.fetchall()}
        if "twitch_multiplier" not in cols:
            await self.db.execute(
                "ALTER TABLE guild_xp_config "
                "ADD COLUMN twitch_multiplier REAL NOT NULL DEFAULT 2.0"
            )
            log.info("Migrated guild_xp_config: added twitch_multiplier column")

        # --- Phase 2 tables (Twitch integration) ---
        # Maps a Twitch account to a Discord user globally (one row per linked pair).
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS linked_accounts (
                twitch_user_id  INTEGER PRIMARY KEY,
                twitch_login    TEXT,
                discord_user_id INTEGER NOT NULL,
                linked_at       TEXT
            )
        """)
        await self.db.execute("""
            CREATE INDEX IF NOT EXISTS idx_linked_accounts_discord_user_id
            ON linked_accounts (discord_user_id)
        """)
        # Short-lived codes used by /twitch-link → !link <CODE> flow.
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS pending_link_codes (
                code            TEXT PRIMARY KEY,
                discord_user_id INTEGER NOT NULL,
                created_at      TEXT,
                expires_at      TEXT
            )
        """)
        # Maps a Discord guild to the Twitch channel whose chat earns XP.
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS guild_twitch_config (
                guild_id              INTEGER PRIMARY KEY,
                twitch_channel        TEXT,
                twitch_broadcaster_id INTEGER
            )
        """)
        # Short-lived pending channel-link requests awaiting !approve-xp in Twitch chat.
        # The bot joins the channel temporarily so it can receive the approval message.
        # A row here does NOT grant XP — only a guild_twitch_config row does.
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS pending_twitch_setup (
                guild_id              INTEGER PRIMARY KEY,
                twitch_channel        TEXT,
                twitch_broadcaster_id INTEGER,
                requested_by_id       INTEGER,
                requested_by_name     TEXT,
                created_at            TEXT,
                expires_at            TEXT
            )
        """)
        await self.db.execute("""
            CREATE INDEX IF NOT EXISTS idx_pending_twitch_setup_broadcaster
            ON pending_twitch_setup (twitch_broadcaster_id)
        """)

        # --- Phase 4 tables (Card notification system) --- #
        # Per-guild configuration for go-live card notifications.
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS guild_card_config (
                guild_id                INTEGER PRIMARY KEY,
                -- Discord channel ID where go-live cards are posted.
                announce_channel_id     INTEGER,
                -- Mention setting: 0=none, -1=@everyone, positive int=role ID.
                mention_setting         INTEGER NOT NULL DEFAULT 0,
                -- Custom message line shown on the card and in the post text.
                custom_message          TEXT NOT NULL DEFAULT 'is now LIVE on Twitch!',
                -- URL supplied by the admin for the go-live background image.
                background_url          TEXT,
                -- Local cache path of the validated go-live background image.
                background_cache_path   TEXT,
                -- ISO-8601 timestamp of last go-live background ingestion.
                background_cached_at    TEXT,
                -- URL supplied by the admin for the rank-card background image.
                rank_background_url       TEXT,
                -- Local cache path of the validated rank-card background image.
                rank_background_cache_path TEXT,
                -- ISO-8601 timestamp of last rank background ingestion.
                rank_background_cached_at  TEXT
            )
        """)

        # Additive migration: add rank background columns to guild_card_config
        # rows created before Phase 2 (Rank Cards) was added.
        async with self.db.execute("PRAGMA table_info(guild_card_config)") as cur:
            gcc_cols = {row["name"] for row in await cur.fetchall()}
        for _col, _dflt in (
            ("rank_background_url", "NULL"),
            ("rank_background_cache_path", "NULL"),
            ("rank_background_cached_at", "NULL"),
        ):
            if _col not in gcc_cols:
                await self.db.execute(
                    f"ALTER TABLE guild_card_config ADD COLUMN {_col} TEXT"
                )
                log.info("Migrated guild_card_config: added %s column", _col)

        # Additive migration: add level-up banner columns to guild_card_config
        # rows created before Phase 3 (Level-Up Banners) was added.
        # Re-query after the rank-background migration so gcc_cols is fresh.
        async with self.db.execute("PRAGMA table_info(guild_card_config)") as cur:
            gcc_cols = {row["name"] for row in await cur.fetchall()}
        for _col in (
            "levelup_background_url",
            "levelup_background_cache_path",
            "levelup_background_cached_at",
            "levelup_announce_channel_id",
            "levelup_message",
        ):
            if _col not in gcc_cols:
                await self.db.execute(
                    f"ALTER TABLE guild_card_config ADD COLUMN {_col} TEXT"
                )
                log.info("Migrated guild_card_config: added %s column", _col)

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
        # Start the Twitch client once the Discord bot (and DB) are ready.
        # This avoids any ordering issue between setup_hook and asyncio.gather.
        if twitch_enabled and not getattr(self, "_twitch_started", False):
            self._twitch_started = True
            asyncio.create_task(_start_twitch_client())


bot = ModminBot()


async def _start_twitch_client() -> None:
    """Build and start the TwitchBot, loading initial channels from the DB.

    Called once from on_ready so we know setup_hook (and thus the DB) is ready.
    Safe to call only when twitch_enabled is True.

    Before constructing TwitchBot, exchanges the stored refresh token for a
    fresh user access token so every startup self-heals into a valid ~4 h token
    even when the previously-stored access token has expired.
    """
    global twitch_client
    assert bot.db is not None

    async with bot.db.execute(
        "SELECT twitch_channel FROM guild_twitch_config WHERE twitch_channel IS NOT NULL"
    ) as cur:
        channel_rows = await cur.fetchall()
    initial_channels = [r["twitch_channel"] for r in channel_rows]

    if not initial_channels:
        log.info("Twitch: no channels configured yet; joining when /twitch-setup is run")

    # Refresh the user access token before connecting so we never start with a
    # stale token.  On failure we log and bail — Discord keeps running.
    refreshed = await _refresh_twitch_user_token()
    if not refreshed:
        log.error(
            "Twitch client: token refresh failed at startup — Twitch integration "
            "disabled for this run. Re-run twitch_auth.py to mint new tokens, "
            "update .env, and restart the service."
        )
        return

    fresh_token = _twitch_user_token["access_token"]

    try:
        tc = TwitchBot(token=fresh_token, initial_channels=initial_channels)  # type: ignore[name-defined]
        twitch_client = tc
        await tc.start()
    except Exception as exc:
        log.error("Twitch client crashed: %s", exc, exc_info=True)
        # Do NOT re-raise — Discord bot must keep running.


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
# XP helpers — shared award core (used by both Discord and Twitch paths)
# --------------------------------------------------------------------------- #


async def _award_xp(
    db: aiosqlite.Connection,
    guild_id: int,
    user_id: int,
    source: str = "discord",
) -> Optional[tuple[int, int, int, int]]:
    """Try to award XP to a user in a guild.

    Returns (gained, new_xp, old_level, new_level) on success, or None if the
    user is on cooldown or XP is disabled for the guild.

    This is the SHARED core used by both the Discord on_message handler and the
    Twitch chat handler so the logic (cooldown, XP range, level math) stays in
    one place. `source` selects the rate: "discord" awards the base range, while
    "twitch" scales it by the guild's twitch_multiplier (default 2.0x).
    """
    config = await _get_guild_xp_config(db, guild_id)
    if not config["enabled"]:
        return None

    cooldown_secs: int = config["cooldown_secs"]
    xp_min: int = config["xp_min"]
    xp_max: int = config["xp_max"]
    multiplier: float = config["twitch_multiplier"] if source == "twitch" else 1.0

    row = await _get_user_xp_row(db, guild_id, user_id)

    # Cooldown check — compare UTC timestamps stored as ISO-8601 strings.
    if row["last_xp_at"] is not None:
        last = datetime.fromisoformat(row["last_xp_at"])
        if (utcnow() - last).total_seconds() < cooldown_secs:
            return None  # still on cooldown

    # Roll the base range, then scale by the source multiplier (Discord = 1.0x).
    gained = round(random.randint(xp_min, xp_max) * multiplier)
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
    return (gained, new_xp, old_level, new_level)


# --------------------------------------------------------------------------- #
# on_message — award XP (Discord path)
# --------------------------------------------------------------------------- #


@bot.event
async def on_message(message: discord.Message) -> None:
    """Award XP for Discord messages, respecting per-guild config and per-user cooldown."""
    # Ignore bots (including ourselves) and DMs.
    if message.author.bot or message.guild is None:
        return

    db = bot.db
    if db is None:
        return  # DB not yet ready (startup race guard)

    guild_id = message.guild.id
    user_id = message.author.id

    try:
        result = await _award_xp(db, guild_id, user_id)
        if result is None:
            return  # disabled or on cooldown

        _gained, _new_xp, old_level, new_level = result

        # Level-up announcement (public, best-effort).
        if new_level > old_level:
            config = await _get_guild_xp_config(db, guild_id)
            await _announce_level_up(
                guild=message.guild,
                member=message.author,
                new_level=new_level,
                level_up_channel_id=config["level_up_channel_id"],
                fallback_channel=message.channel if isinstance(
                    message.channel, discord.TextChannel
                ) else None,
            )

    except Exception as exc:
        log.warning("XP award failed for user %s in guild %s: %s", user_id, guild_id, exc)


async def _announce_level_up(
    guild: discord.Guild,
    member: discord.abc.User,
    new_level: int,
    level_up_channel_id: Optional[int],
    fallback_channel: Optional[discord.TextChannel] = None,
) -> None:
    """Post a level-up announcement.  Best-effort; swallows all HTTP errors.

    Tries in order:
      1. Render a level-up banner card and post it to the configured level-up
         announce channel (from guild_card_config.levelup_announce_channel_id).
      2. If the card system is unavailable or rendering fails, post a plain
         embed to the same channel.
      3. If no levelup channel is configured in guild_card_config, fall back to
         guild_xp_config.level_up_channel_id or the Discord message channel.

    A per-user debounce (LEVELUP_DEBOUNCE_SECS) is applied before any network
    work to collapse rapid consecutive level-ups (e.g. from an XP burst) into
    a single announcement for the highest level reached.

    Works for both Discord messages (pass fallback_channel) and Twitch-triggered
    level-ups (fallback_channel=None).
    """
    user_id: int = member.id

    # --- Debounce check -------------------------------------------------------
    now = utcnow()
    debounce_key = (guild.id, user_id)
    last_announced = _levelup_last_notified.get(debounce_key)
    if last_announced is not None:
        elapsed = (now - last_announced).total_seconds()
        if elapsed < LEVELUP_DEBOUNCE_SECS:
            log.debug(
                "level-up debounced for user %s guild %s (%.1fs since last)",
                user_id, guild.id, elapsed,
            )
            return
    _levelup_last_notified[debounce_key] = now

    db = bot.db

    # --- Try to load level-up card config from guild_card_config ---------------
    levelup_channel_id: Optional[int] = None
    levelup_bg_path: Optional[str] = None
    levelup_message: str = "{mention} just levelled up!"

    if db is not None:
        try:
            async with db.execute(
                "SELECT levelup_announce_channel_id, levelup_background_cache_path, "
                "       levelup_message "
                "FROM guild_card_config WHERE guild_id = ?",
                (guild.id,),
            ) as cur:
                luc_row = await cur.fetchone()
            if luc_row is not None:
                if luc_row["levelup_announce_channel_id"] is not None:
                    levelup_channel_id = int(luc_row["levelup_announce_channel_id"])
                if luc_row["levelup_background_cache_path"]:
                    levelup_bg_path = luc_row["levelup_background_cache_path"]
                if luc_row["levelup_message"]:
                    levelup_message = luc_row["levelup_message"]
        except Exception as exc:
            log.warning("_announce_level_up: could not read level-up card config: %s", exc)

    # --- Resolve destination channel ------------------------------------------
    # Priority: levelup-specific channel > xp level_up_channel_id > fallback_channel.
    dest: Optional[discord.TextChannel] = None
    if levelup_channel_id:
        ch = guild.get_channel(levelup_channel_id)
        if isinstance(ch, discord.TextChannel):
            dest = ch
    if dest is None and level_up_channel_id:
        ch = guild.get_channel(level_up_channel_id)
        if isinstance(ch, discord.TextChannel):
            dest = ch
    if dest is None:
        dest = fallback_channel

    if dest is None:
        return

    if not dest.permissions_for(guild.me).send_messages:
        return

    # --- Build the plain embed (always; used as fallback) ----------------------
    display_name: str = getattr(member, "display_name", str(member))
    # Resolve {mention} and {level} placeholders in the configured message.
    resolved_message = levelup_message.replace("{mention}", member.mention).replace(
        "{level}", str(new_level)
    )
    embed = discord.Embed(
        description=f"🎉 {member.mention} reached **level {new_level}**!\n{resolved_message}",
        color=discord.Color.gold(),
        timestamp=now,
    )
    if hasattr(member, "display_avatar") and member.display_avatar:
        embed.set_thumbnail(url=member.display_avatar.url)
    embed.set_footer(text=f"{guild.name} XP System")

    # --- Attempt to render the banner card if configured ----------------------
    card_file: Optional[discord.File] = None
    if _CARDS_AVAILABLE and levelup_bg_path:
        try:
            # Fetch the Discord avatar bytes.
            avatar_bytes: Optional[bytes] = None
            if hasattr(member, "display_avatar") and member.display_avatar:
                try:
                    avatar_bytes = await member.display_avatar.read()
                except Exception as av_exc:
                    log.debug(
                        "_announce_level_up: could not fetch avatar for user %s: %s",
                        user_id, av_exc,
                    )

            card_png = await asyncio.to_thread(
                render_levelup_card,
                display_name,
                new_level,
                levelup_bg_path,
                avatar_bytes,
                resolved_message,
            )
            card_file = discord.File(
                io.BytesIO(card_png),
                filename=f"levelup_{user_id}.png",
            )
        except Exception as exc:
            log.warning(
                "_announce_level_up: card render failed for user %s: %s; "
                "falling back to plain embed",
                user_id, exc,
            )
            card_file = None

    # --- Send ----------------------------------------------------------------
    try:
        if card_file is not None:
            await dest.send(content=f"🎉 {member.mention} reached **level {new_level}**!", file=card_file)
        else:
            await dest.send(embed=embed)
    except discord.HTTPException as exc:
        log.warning("Level-up announcement failed: %s", exc)


# --------------------------------------------------------------------------- #
# Twitch — user-token refresh (keeps bot-account token alive across restarts)
# --------------------------------------------------------------------------- #

# Module-level mutable holder so _start_twitch_client can update the token
# after a refresh without requiring a global declaration everywhere.
_twitch_user_token: dict[str, str] = {
    "access_token": TWITCH_BOT_ACCESS_TOKEN,
    "refresh_token": TWITCH_BOT_REFRESH_TOKEN,
}

# Absolute path to the .env file the service loads (same directory as bot.py).
_ENV_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")


async def _refresh_twitch_user_token() -> bool:
    """Exchange the stored refresh token for a fresh Twitch user access token.

    Posts to https://id.twitch.tv/oauth2/token with grant_type=refresh_token,
    updates _twitch_user_token in-memory, and persists both tokens back to the
    .env file so the NEXT service restart also has a valid token.

    Returns True on success, False on any error (caller handles graceful skip).
    """
    if not (TWITCH_CLIENT_ID and TWITCH_CLIENT_SECRET and _AIOHTTP_AVAILABLE):
        log.warning("Twitch token refresh: missing client_id/secret or aiohttp unavailable")
        return False

    refresh_token = _twitch_user_token["refresh_token"]
    if not refresh_token:
        log.error(
            "Twitch token refresh: no refresh token available. "
            "Re-mint tokens by running twitch_auth.py and updating .env."
        )
        return False

    log.info("Twitch token refresh: exchanging refresh token for a fresh user access token")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://id.twitch.tv/oauth2/token",
                params={
                    "client_id": TWITCH_CLIENT_ID,
                    "client_secret": TWITCH_CLIENT_SECRET,
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                },
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    log.error(
                        "Twitch token refresh: HTTP %s from Twitch — refresh token may be "
                        "revoked. Re-run twitch_auth.py to mint new tokens. Response: %s",
                        resp.status, body[:200],
                    )
                    return False
                data = await resp.json()
    except Exception as exc:
        log.error("Twitch token refresh: network error: %s", exc)
        return False

    new_access = data.get("access_token", "")
    new_refresh = data.get("refresh_token", "") or refresh_token  # Twitch may not rotate
    if not new_access:
        log.error("Twitch token refresh: response contained no access_token: %s", data)
        return False

    _twitch_user_token["access_token"] = new_access
    _twitch_user_token["refresh_token"] = new_refresh
    log.info("Twitch token refresh: got fresh access token (refresh_token %s)",
             "rotated" if new_refresh != refresh_token else "unchanged")

    _persist_twitch_tokens(new_access, new_refresh)
    return True


def _persist_twitch_tokens(access_token: str, refresh_token: str) -> None:
    """Rewrite TWITCH_BOT_ACCESS_TOKEN and TWITCH_BOT_REFRESH_TOKEN in the .env file.

    Only those two lines are changed; all other lines are preserved exactly.
    If the .env file does not exist or cannot be written, logs a warning but
    does NOT raise — the in-memory token is already valid for this run.
    """
    if not os.path.isfile(_ENV_FILE):
        log.warning(
            "Twitch token persist: .env not found at %s — tokens updated in memory only",
            _ENV_FILE,
        )
        return

    try:
        with open(_ENV_FILE, "r", encoding="utf-8") as fh:
            lines = fh.readlines()

        new_lines: list[str] = []
        found_access = False
        found_refresh = False
        for line in lines:
            stripped = line.lstrip()
            if stripped.startswith("TWITCH_BOT_ACCESS_TOKEN="):
                new_lines.append(f"TWITCH_BOT_ACCESS_TOKEN={access_token}\n")
                found_access = True
            elif stripped.startswith("TWITCH_BOT_REFRESH_TOKEN="):
                new_lines.append(f"TWITCH_BOT_REFRESH_TOKEN={refresh_token}\n")
                found_refresh = True
            else:
                new_lines.append(line)

        # Append any keys that were missing entirely (unlikely, but safe).
        if not found_access:
            new_lines.append(f"TWITCH_BOT_ACCESS_TOKEN={access_token}\n")
            log.warning("Twitch token persist: TWITCH_BOT_ACCESS_TOKEN was not in .env; appended")
        if not found_refresh:
            new_lines.append(f"TWITCH_BOT_REFRESH_TOKEN={refresh_token}\n")
            log.warning("Twitch token persist: TWITCH_BOT_REFRESH_TOKEN was not in .env; appended")

        with open(_ENV_FILE, "w", encoding="utf-8") as fh:
            fh.writelines(new_lines)

        log.info("Twitch token persist: .env updated at %s", _ENV_FILE)
    except OSError as exc:
        log.warning("Twitch token persist: could not write .env: %s", exc)


# --------------------------------------------------------------------------- #
# Twitch — app-token cache (client_credentials for Helix API calls)
# --------------------------------------------------------------------------- #

_app_token_cache: dict[str, object] = {"token": None, "expires_at": 0.0}


async def _get_app_access_token() -> Optional[str]:
    """Fetch (and cache) a Twitch app access token via client_credentials.

    Returns None if Twitch env vars are absent or aiohttp is unavailable.
    Refreshes automatically when within 60 seconds of expiry.
    """
    if not (TWITCH_CLIENT_ID and TWITCH_CLIENT_SECRET and _AIOHTTP_AVAILABLE):
        return None

    now = time.monotonic()
    if _app_token_cache["token"] and now < float(_app_token_cache["expires_at"]) - 60:
        return str(_app_token_cache["token"])

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://id.twitch.tv/oauth2/token",
                params={
                    "client_id": TWITCH_CLIENT_ID,
                    "client_secret": TWITCH_CLIENT_SECRET,
                    "grant_type": "client_credentials",
                },
            ) as resp:
                if resp.status != 200:
                    log.warning("Twitch app token request failed: HTTP %s", resp.status)
                    return None
                data = await resp.json()
    except Exception as exc:
        log.warning("Twitch app token fetch error: %s", exc)
        return None

    token = data.get("access_token")
    expires_in = data.get("expires_in", 3600)
    _app_token_cache["token"] = token
    _app_token_cache["expires_at"] = now + expires_in
    return token


# --------------------------------------------------------------------------- #
# Twitch — live check (Phase 3: poll-based, safe-default-offline)
# --------------------------------------------------------------------------- #


async def _channel_is_live(channel_name: str) -> bool:
    """Return True if the Twitch channel is currently live.

    Looks up the broadcaster_id for `channel_name` from guild_twitch_config,
    then checks whether that ID is in the TwitchBot's live_broadcasters set
    (populated every 60 s by _poll_stream_status).

    Safe default: returns False if the twitch client is not ready, the
    broadcaster ID is unknown, or no poll has completed yet.  This means
    chatters earn ZERO XP unless we have positively confirmed the stream is
    live — no false positives on startup or transient API errors.

    Note: !link and !approve-xp are NOT gated by this function; only
    _handle_xp calls it.
    """
    if twitch_client is None:
        return False

    tc = twitch_client  # type: ignore[assignment]
    live: set[int] = getattr(tc, "live_broadcasters", set())

    db = bot.db
    if db is None:
        return False

    # Find any guild_twitch_config row whose twitch_channel matches channel_name.
    # (Multiple guilds can share the same channel, but broadcaster_id is the same.)
    channel_lower = channel_name.lower()
    try:
        async with db.execute(
            "SELECT twitch_broadcaster_id FROM guild_twitch_config"
            " WHERE twitch_channel = ? AND twitch_broadcaster_id IS NOT NULL"
            " LIMIT 1",
            (channel_lower,),
        ) as cur:
            row = await cur.fetchone()
    except Exception as exc:
        log.warning("_channel_is_live DB lookup error for '%s': %s", channel_name, exc)
        return False

    if row is None:
        return False  # channel not configured or broadcaster ID unknown

    broadcaster_id = int(row["twitch_broadcaster_id"])
    return broadcaster_id in live


# --------------------------------------------------------------------------- #
# Twitch — twitchio 2.x client
# --------------------------------------------------------------------------- #

twitch_client: Optional[object] = None  # set below if twitch_enabled

# Debounce: maps broadcaster_id → UTC timestamp of last go-live notification.
# Prevents re-announcing the same stream within GOLIVE_DEBOUNCE_MINUTES of its
# previous notification (handles Twitch stream start flapping).
_golive_last_notified: dict[int, datetime] = {}
GOLIVE_DEBOUNCE_MINUTES: int = 10

# Level-up debounce: maps (guild_id, user_id) → UTC timestamp of last banner.
# Collapses rapid consecutive level-ups (e.g. Twitch message burst during an
# XP spike) into at most one banner every LEVELUP_DEBOUNCE_SECS seconds.
# The XP cooldown makes rapid multi-level-ups from a single source very rare,
# but can happen if a user was near two level boundaries or the Twitch multiplier
# is high.  30 seconds is long enough to absorb a burst but short enough that a
# genuine second level-up reached later in the same session still gets announced.
_levelup_last_notified: dict[tuple[int, int], datetime] = {}
LEVELUP_DEBOUNCE_SECS: int = 30

if twitch_enabled:
    class TwitchBot(twitch_commands.Bot):
        """twitchio 2.x Bot that awards Discord XP for Twitch chat messages."""

        def __init__(self, token: str, initial_channels: list[str]) -> None:
            # twitchio 2.x: token must be bare (no oauth: prefix for ext.commands.Bot).
            # `token` is passed in from _start_twitch_client after being refreshed;
            # never hardcoded from the module-level TWITCH_BOT_ACCESS_TOKEN constant
            # which may be stale after the ~4 h Twitch expiry.
            super().__init__(
                token=token,
                client_secret=TWITCH_CLIENT_SECRET,
                prefix="!",
                initial_channels=initial_channels,
                nick=TWITCH_BOT_USERNAME,
            )
            # Phase 3: set of broadcaster user IDs currently live.
            # Populated (and replaced atomically) by _poll_stream_status every 60s.
            # Starts empty so the safe default is OFFLINE until the first poll completes.
            self.live_broadcasters: set[int] = set()

        async def event_ready(self) -> None:
            log.info("Twitch bot ready | nick: %s", self.nick)
            # Phase 3: start the stream-status poll loop as a background task.
            asyncio.create_task(self._poll_stream_status())

        async def event_error(self, error: Exception, data: str = "") -> None:
            log.error("Twitch client error: %s | data: %s", error, data)

        async def _poll_stream_status(self) -> None:
            """Background task: poll Helix /streams every 60s to update live_broadcasters.

            Runs one poll immediately at startup (before the first sleep) so live status
            is fresh quickly. On any API or network error the previous live_broadcasters
            set is kept intact — we never flap to empty on a transient failure.
            Broadcaster transitions (live→offline, offline→live) are logged at INFO.
            The loop catches all exceptions and continues so it can never kill itself.
            """
            first_run = True
            while True:
                if not first_run:
                    await asyncio.sleep(60)
                first_run = False

                try:
                    db = bot.db
                    if db is None:
                        continue  # DB not ready yet; try again next tick

                    # Collect all distinct broadcaster IDs currently configured.
                    try:
                        async with db.execute(
                            "SELECT DISTINCT twitch_broadcaster_id FROM guild_twitch_config"
                            " WHERE twitch_broadcaster_id IS NOT NULL"
                        ) as cur:
                            id_rows = await cur.fetchall()
                    except Exception as exc:
                        log.warning("Twitch poll: DB query error: %s", exc)
                        continue

                    if not id_rows:
                        # No channels configured — clear the set and wait.
                        self.live_broadcasters = set()
                        continue

                    broadcaster_ids = [int(r["twitch_broadcaster_id"]) for r in id_rows]

                    # Fetch an app access token (cached, auto-refreshed).
                    if not _AIOHTTP_AVAILABLE:
                        continue
                    token = await _get_app_access_token()
                    if not token:
                        log.warning("Twitch poll: could not get app access token; skipping tick")
                        continue

                    # Query Helix /streams for all broadcaster IDs (up to 100 per request).
                    # Helix only returns currently-live streams in the response.
                    new_live: set[int] = set()
                    try:
                        # Batch into groups of 100 (Discord channels will be far fewer in practice).
                        for batch_start in range(0, len(broadcaster_ids), 100):
                            batch = broadcaster_ids[batch_start:batch_start + 100]
                            params = [("user_id", str(bid)) for bid in batch]
                            async with aiohttp.ClientSession() as session:
                                async with session.get(
                                    "https://api.twitch.tv/helix/streams",
                                    params=params,
                                    headers={
                                        "Client-ID": TWITCH_CLIENT_ID,
                                        "Authorization": f"Bearer {token}",
                                    },
                                ) as resp:
                                    if resp.status != 200:
                                        log.warning(
                                            "Twitch poll: Helix /streams returned HTTP %s; "
                                            "keeping previous live set",
                                            resp.status,
                                        )
                                        # On non-200, bail out of the whole tick without
                                        # replacing live_broadcasters (keep prior state).
                                        new_live = None  # type: ignore[assignment]
                                        break
                                    data = await resp.json()
                                    for stream in data.get("data", []):
                                        if stream.get("type") == "live":
                                            try:
                                                new_live.add(int(stream["user_id"]))
                                            except (KeyError, ValueError):
                                                pass
                    except Exception as exc:
                        log.warning(
                            "Twitch poll: API request error: %s; keeping previous live set", exc
                        )
                        continue  # keep previous self.live_broadcasters on error

                    if new_live is None:
                        # Non-200 from Helix — keep previous state (already logged above).
                        continue

                    # Log transitions before replacing the set.
                    prev = self.live_broadcasters
                    went_live = new_live - prev
                    went_offline = prev - new_live
                    for bid in went_live:
                        log.info("Twitch stream went LIVE: broadcaster_id=%s", bid)
                    for bid in went_offline:
                        log.info("Twitch stream went OFFLINE: broadcaster_id=%s", bid)

                    # Atomic replacement.
                    self.live_broadcasters = new_live

                    # Dispatch go-live card notifications for newly-live broadcasters.
                    if went_live and db is not None:
                        for bid in went_live:
                            asyncio.create_task(
                                _dispatch_golive_notification(db, bid, token)
                            )

                except Exception as exc:
                    # Catch-all: log and continue so the loop never dies.
                    log.warning("Twitch poll: unexpected error in poll tick: %s", exc, exc_info=True)

        async def event_message(self, message: twitchio.Message) -> None:
            """Handle incoming Twitch chat messages."""
            # Ignore messages from the bot itself.
            if message.echo:
                return

            content = message.content.strip()
            channel_name = message.channel.name.lower()

            # ---- !approve-xp handler (must check BEFORE XP path) ------------
            if content.lower() == "!approve-xp":
                await self._handle_approve_xp(message, channel_name)
                return

            # ---- !link <CODE> handler ----------------------------------------
            parts = content.split()
            if len(parts) == 2 and parts[0].lower() == "!link":
                await self._handle_link(message, parts[1].upper(), channel_name)
                return

            # ---- Normal chat → XP award -------------------------------------
            await self._handle_xp(message, channel_name)

        async def _handle_link(
            self,
            message: twitchio.Message,
            code: str,
            channel_name: str,
        ) -> None:
            """Process a !link <CODE> command from Twitch chat."""
            db = bot.db
            if db is None:
                return

            twitch_user = message.author
            twitch_user_id = int(twitch_user.id)
            twitch_login = twitch_user.name.lower()
            now = utcnow()

            try:
                # Look up the code (case-insensitive).
                async with db.execute(
                    "SELECT * FROM pending_link_codes WHERE code = ?", (code,)
                ) as cur:
                    code_row = await cur.fetchone()

                if code_row is None:
                    try:
                        await message.channel.send(
                            f"@{twitch_user.name} That link code wasn't found. "
                            "Use /twitch-link in Discord to get a fresh code."
                        )
                    except Exception:
                        pass
                    return

                # Check expiry.
                expires_at = datetime.fromisoformat(code_row["expires_at"])
                if now > expires_at:
                    await db.execute(
                        "DELETE FROM pending_link_codes WHERE code = ?", (code,)
                    )
                    await db.commit()
                    try:
                        await message.channel.send(
                            f"@{twitch_user.name} That code has expired. "
                            "Use /twitch-link in Discord to get a new one."
                        )
                    except Exception:
                        pass
                    return

                discord_user_id = code_row["discord_user_id"]

                # Upsert the linked_accounts row.
                await db.execute(
                    """
                    INSERT INTO linked_accounts
                        (twitch_user_id, twitch_login, discord_user_id, linked_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(twitch_user_id) DO UPDATE SET
                        twitch_login    = excluded.twitch_login,
                        discord_user_id = excluded.discord_user_id,
                        linked_at       = excluded.linked_at
                    """,
                    (twitch_user_id, twitch_login, discord_user_id, now.isoformat()),
                )
                # Delete the used code.
                await db.execute(
                    "DELETE FROM pending_link_codes WHERE code = ?", (code,)
                )
                await db.commit()

                log.info(
                    "Twitch link: twitch_user_id=%s (%s) → discord_user_id=%s",
                    twitch_user_id, twitch_login, discord_user_id,
                )

                # Confirm in Twitch chat (best-effort).
                try:
                    await message.channel.send(
                        f"@{twitch_user.name} Successfully linked! "
                        "You'll now earn Discord XP from Twitch chat."
                    )
                except Exception:
                    pass

                # Best-effort DM the Discord user.
                try:
                    discord_user = await bot.fetch_user(discord_user_id)
                    if discord_user:
                        await discord_user.send(
                            f"Your Twitch account **{twitch_user.name}** has been linked "
                            "to your Discord account. You'll earn XP in Discord servers "
                            "that have Twitch integration enabled by chatting on Twitch!"
                        )
                except Exception:
                    pass

            except Exception as exc:
                log.warning("Twitch !link handler error: %s", exc)

        async def _handle_approve_xp(
            self,
            message: twitchio.Message,
            channel_name: str,
        ) -> None:
            """Process a !approve-xp command from Twitch chat.

            Only the channel broadcaster (is_broadcaster=True) can approve.
            Silently ignores all other chatters to avoid leaking state.
            Finalises any non-expired pending_twitch_setup row for this channel.
            """
            # Ownership proof: only the real broadcaster has is_broadcaster.
            if not getattr(message.author, "is_broadcaster", False):
                return  # not the broadcaster — ignore silently

            db = bot.db
            if db is None:
                return

            now = utcnow()
            try:
                # Look up a non-expired pending row for this exact channel.
                async with db.execute(
                    """
                    SELECT * FROM pending_twitch_setup
                    WHERE twitch_channel = ?
                    ORDER BY created_at DESC
                    LIMIT 1
                    """,
                    (channel_name,),
                ) as cur:
                    pending = await cur.fetchone()

                if pending is None:
                    # No pending request at all.
                    try:
                        await message.channel.send(
                            "There is no pending link request for this channel."
                        )
                    except Exception:
                        pass
                    return

                expires_at = datetime.fromisoformat(pending["expires_at"])
                if now > expires_at:
                    # Request expired — clean it up.
                    await db.execute(
                        "DELETE FROM pending_twitch_setup WHERE guild_id = ?",
                        (pending["guild_id"],),
                    )
                    await db.commit()
                    # Part if no approved config exists.
                    await self._part_if_no_config(channel_name, pending["guild_id"])
                    try:
                        await message.channel.send(
                            "The link request for this channel has expired. "
                            "The Discord server owner can run /twitch-setup again."
                        )
                    except Exception:
                        pass
                    return

                # Verify the broadcaster ID matches the author.
                author_id = int(message.author.id)
                if author_id != pending["twitch_broadcaster_id"]:
                    # Channel name matched but broadcaster ID didn't — silent.
                    return

                guild_id = pending["guild_id"]
                guild_name: str = pending["guild_id"]  # fallback if guild not cached
                discord_guild = bot.get_guild(guild_id)
                if discord_guild is not None:
                    guild_name = discord_guild.name

                # Finalise: upsert guild_twitch_config and delete the pending row.
                await db.execute(
                    """
                    INSERT INTO guild_twitch_config
                        (guild_id, twitch_channel, twitch_broadcaster_id)
                    VALUES (?, ?, ?)
                    ON CONFLICT(guild_id) DO UPDATE SET
                        twitch_channel        = excluded.twitch_channel,
                        twitch_broadcaster_id = excluded.twitch_broadcaster_id
                    """,
                    (guild_id, channel_name, pending["twitch_broadcaster_id"]),
                )
                await db.execute(
                    "DELETE FROM pending_twitch_setup WHERE guild_id = ?",
                    (guild_id,),
                )
                await db.commit()

                log.info(
                    "Twitch channel '%s' approved for guild %s by broadcaster %s",
                    channel_name, guild_id, author_id,
                )

                # Confirm in Twitch chat.
                try:
                    await message.channel.send(
                        f"✅ Approved! Chatters in this channel now earn XP "
                        f"in the Discord server '{guild_name}'."
                    )
                except Exception:
                    pass

                # Best-effort DM the original Discord requester.
                requester_id = pending["requested_by_id"]
                try:
                    discord_requester = await bot.fetch_user(requester_id)
                    if discord_requester:
                        await discord_requester.send(
                            f"Your request to link Twitch channel **{channel_name}** "
                            f"to **{guild_name}** was approved by the channel owner. "
                            "Chatters who link their accounts will now earn Discord XP!"
                        )
                except Exception:
                    pass

                # Mod-log the approval in Discord.
                if discord_guild is not None:
                    embed = discord.Embed(
                        title="Twitch Channel Link Approved",
                        description=(
                            f"Twitch channel **{channel_name}** was approved by its "
                            f"broadcaster and is now linked to **{discord_guild.name}**."
                        ),
                        color=discord.Color.green(),
                        timestamp=utcnow(),
                    )
                    embed.add_field(name="Twitch Channel", value=channel_name)
                    embed.add_field(name="Broadcaster ID", value=str(pending["twitch_broadcaster_id"]))
                    embed.add_field(
                        name="Originally Requested By",
                        value=f"<@{requester_id}> ({pending['requested_by_name']})",
                        inline=False,
                    )
                    await send_mod_log(discord_guild, embed)

            except Exception as exc:
                log.warning("Twitch !approve-xp handler error: %s", exc)

        async def _part_if_no_config(self, channel_name: str, guild_id: int) -> None:
            """Part a Twitch channel if there is no approved guild_twitch_config for it.

            Called when a pending request expires, so the bot doesn't linger in channels
            it was only joined to for the consent handshake.
            """
            db = bot.db
            if db is None:
                return
            try:
                # Check if any guild has an approved config pointing to this channel.
                async with db.execute(
                    "SELECT 1 FROM guild_twitch_config WHERE twitch_channel = ? LIMIT 1",
                    (channel_name,),
                ) as cur:
                    row = await cur.fetchone()
                if row is not None:
                    return  # still needed for an approved guild

                # Check if any OTHER non-expired pending request exists for this channel.
                async with db.execute(
                    """
                    SELECT 1 FROM pending_twitch_setup
                    WHERE twitch_channel = ? AND expires_at > ?
                    LIMIT 1
                    """,
                    (channel_name, utcnow().isoformat()),
                ) as cur:
                    row = await cur.fetchone()
                if row is not None:
                    return  # another pending request is still alive

                # Safe to part.
                existing = [ch.name.lower() for ch in self.connected_channels]
                if channel_name in existing:
                    await self.part_channels([channel_name])
                    log.info(
                        "Twitch client parted channel '%s' — pending expired, no approved config",
                        channel_name,
                    )
            except Exception as exc:
                log.warning("_part_if_no_config error for channel '%s': %s", channel_name, exc)

        async def _handle_xp(
            self, message: twitchio.Message, channel_name: str
        ) -> None:
            """Award Discord XP for a normal Twitch chat message."""
            # Gate on stream being live (Phase 3 seam).
            if not await _channel_is_live(channel_name):
                return

            db = bot.db
            if db is None:
                return

            twitch_user_id = int(message.author.id)

            try:
                # Resolve Twitch user → Discord user.
                async with db.execute(
                    "SELECT discord_user_id FROM linked_accounts WHERE twitch_user_id = ?",
                    (twitch_user_id,),
                ) as cur:
                    link_row = await cur.fetchone()

                if link_row is None:
                    return  # chatter has no linked Discord account

                discord_user_id = link_row["discord_user_id"]

                # Find all Discord guilds mapped to this Twitch channel.
                async with db.execute(
                    "SELECT guild_id FROM guild_twitch_config WHERE twitch_channel = ?",
                    (channel_name,),
                ) as cur:
                    guild_rows = await cur.fetchall()

                for guild_row in guild_rows:
                    guild_id = guild_row["guild_id"]
                    guild = bot.get_guild(guild_id)
                    if guild is None:
                        continue  # bot not in this guild (yet)

                    try:
                        result = await _award_xp(
                            db, guild_id, discord_user_id, source="twitch"
                        )
                        if result is None:
                            continue  # disabled or on cooldown

                        _gained, _new_xp, old_level, new_level = result

                        if new_level > old_level:
                            config = await _get_guild_xp_config(db, guild_id)
                            member = guild.get_member(discord_user_id)
                            if member is not None:
                                await _announce_level_up(
                                    guild=guild,
                                    member=member,
                                    new_level=new_level,
                                    level_up_channel_id=config["level_up_channel_id"],
                                    fallback_channel=None,
                                )
                    except Exception as exc:
                        log.warning(
                            "Twitch XP award error for discord_user_id=%s guild=%s: %s",
                            discord_user_id, guild_id, exc,
                        )

            except Exception as exc:
                log.warning("Twitch XP handler error: %s", exc)


# --------------------------------------------------------------------------- #
# Go-live card notification dispatcher
# --------------------------------------------------------------------------- #


async def _fetch_twitch_avatar_bytes(
    broadcaster_login: str, token: Optional[str]
) -> Optional[bytes]:
    """Best-effort fetch of the Twitch broadcaster's profile image bytes.

    Returns None on any failure — the card falls back to a placeholder.
    """
    if not (TWITCH_CLIENT_ID and token and _AIOHTTP_AVAILABLE):
        return None
    try:
        import aiohttp as _aio
        async with _aio.ClientSession() as session:
            async with session.get(
                "https://api.twitch.tv/helix/users",
                params={"login": broadcaster_login},
                headers={
                    "Client-ID": TWITCH_CLIENT_ID,
                    "Authorization": f"Bearer {token}",
                },
                timeout=_aio.ClientTimeout(total=8),
            ) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json()
                users = data.get("data", [])
                if not users:
                    return None
                profile_url = users[0].get("profile_image_url", "")
                if not profile_url or not profile_url.startswith("https://"):
                    return None

            async with session.get(
                profile_url, timeout=_aio.ClientTimeout(total=8)
            ) as img_resp:
                if img_resp.status != 200:
                    return None
                ct = img_resp.content_type.lower()
                if not ct.startswith("image/"):
                    return None
                return await img_resp.read()
    except Exception as exc:
        log.debug("Could not fetch Twitch avatar for '%s': %s", broadcaster_login, exc)
        return None


async def _fetch_twitch_stream_info(
    broadcaster_id: int, token: Optional[str]
) -> tuple[str, str, str]:
    """Return (display_name, login, title) for a live broadcaster.

    Queries Helix /streams; falls back to empty strings on any error.
    """
    if not (TWITCH_CLIENT_ID and token and _AIOHTTP_AVAILABLE):
        return ("", "", "")
    try:
        import aiohttp as _aio
        async with _aio.ClientSession() as session:
            async with session.get(
                "https://api.twitch.tv/helix/streams",
                params={"user_id": str(broadcaster_id)},
                headers={
                    "Client-ID": TWITCH_CLIENT_ID,
                    "Authorization": f"Bearer {token}",
                },
                timeout=_aio.ClientTimeout(total=8),
            ) as resp:
                if resp.status != 200:
                    return ("", "", "")
                data = await resp.json()
                streams = data.get("data", [])
                if not streams:
                    return ("", "", "")
                s = streams[0]
                return (
                    s.get("user_name", ""),   # display name
                    s.get("user_login", ""),  # login name (for avatar lookup)
                    s.get("title", ""),
                )
    except Exception as exc:
        log.debug("Could not fetch stream info for broadcaster %s: %s", broadcaster_id, exc)
        return ("", "", "")


async def _dispatch_golive_notification(
    db: aiosqlite.Connection,
    broadcaster_id: int,
    token: Optional[str],
) -> None:
    """Send go-live card notifications for all guilds configured for this broadcaster.

    Called as a background task when a broadcaster transitions offline→live.
    Includes debounce to prevent re-firing within GOLIVE_DEBOUNCE_MINUTES of
    the previous notification.  Falls back to a plain embed if the card system
    is unavailable or fails.
    """
    now = utcnow()

    # --- Debounce check -------------------------------------------------------
    last = _golive_last_notified.get(broadcaster_id)
    if last is not None:
        elapsed = (now - last).total_seconds() / 60
        if elapsed < GOLIVE_DEBOUNCE_MINUTES:
            log.info(
                "go-live notify: broadcaster %s debounced (%.1f min since last)",
                broadcaster_id, elapsed,
            )
            return

    # --- Fetch stream metadata ------------------------------------------------
    display_name, login_name, stream_title = await _fetch_twitch_stream_info(
        broadcaster_id, token
    )
    if not display_name:
        # Try looking up login from DB as a fallback.
        try:
            async with db.execute(
                "SELECT twitch_channel FROM guild_twitch_config"
                " WHERE twitch_broadcaster_id = ? LIMIT 1",
                (broadcaster_id,),
            ) as cur:
                row = await cur.fetchone()
            if row:
                login_name = row["twitch_channel"]
                display_name = login_name
        except Exception:
            pass

    if not display_name:
        display_name = f"Broadcaster {broadcaster_id}"
        login_name = ""

    log.info(
        "go-live notify: dispatching for broadcaster %s ('%s'), title='%s'",
        broadcaster_id, display_name, stream_title,
    )

    # --- Fetch avatar (best-effort) ------------------------------------------
    avatar_bytes: Optional[bytes] = None
    if login_name:
        avatar_bytes = await _fetch_twitch_avatar_bytes(login_name, token)

    # --- Find all guilds configured for this broadcaster ---------------------
    try:
        async with db.execute(
            "SELECT gtc.guild_id, gcc.announce_channel_id, gcc.mention_setting, "
            "       gcc.custom_message, gcc.background_cache_path "
            "FROM guild_twitch_config gtc "
            "LEFT JOIN guild_card_config gcc ON gtc.guild_id = gcc.guild_id "
            "WHERE gtc.twitch_broadcaster_id = ?",
            (broadcaster_id,),
        ) as cur:
            guild_rows = await cur.fetchall()
    except Exception as exc:
        log.warning("go-live notify: DB query error for broadcaster %s: %s", broadcaster_id, exc)
        return

    if not guild_rows:
        log.debug("go-live notify: no guilds for broadcaster %s", broadcaster_id)
        return

    # --- Record debounce timestamp before sending (prevents double-fire) ------
    _golive_last_notified[broadcaster_id] = now

    # --- Build card bytes once (reused for every guild) ----------------------
    card_bytes: Optional[bytes] = None
    if _CARDS_AVAILABLE:
        try:
            custom_msg = None
            bg_path = None
            for row in guild_rows:
                if row["custom_message"]:
                    custom_msg = row["custom_message"]
                    bg_path = row["background_cache_path"]
                    break
            card_bytes = await asyncio.to_thread(
                render_card,
                display_name,
                stream_title,
                bg_path,
                avatar_bytes,
                custom_msg or "is now LIVE on Twitch!",
            )
        except Exception as exc:
            log.warning(
                "go-live notify: card render failed for broadcaster %s: %s; "
                "falling back to plain embed",
                broadcaster_id, exc,
            )
            card_bytes = None

    # --- Send to each guild ---------------------------------------------------
    for row in guild_rows:
        guild_id = row["guild_id"]
        announce_channel_id = row["announce_channel_id"]
        mention_setting = row["mention_setting"] if row["mention_setting"] is not None else 0
        custom_message = row["custom_message"] or "is now LIVE on Twitch!"
        bg_path = row["background_cache_path"]

        guild = bot.get_guild(guild_id)
        if guild is None:
            log.debug("go-live notify: bot not in guild %s, skipping", guild_id)
            continue

        # Resolve announcement channel.
        dest: Optional[discord.TextChannel] = None
        if announce_channel_id:
            ch = guild.get_channel(announce_channel_id)
            if isinstance(ch, discord.TextChannel):
                dest = ch
        if dest is None:
            log.info(
                "go-live notify: guild %s has no announcement channel configured; skipping",
                guild_id,
            )
            continue

        if not dest.permissions_for(guild.me).send_messages:
            log.warning(
                "go-live notify: no send permission in #%s (guild %s)",
                dest.name, guild_id,
            )
            continue

        # Build mention prefix.
        mention_prefix = ""
        if mention_setting == -1:
            mention_prefix = "@everyone "
        elif mention_setting and mention_setting > 0:
            role = guild.get_role(mention_setting)
            if role:
                mention_prefix = f"{role.mention} "

        twitch_url = f"https://twitch.tv/{login_name}" if login_name else "https://twitch.tv"
        notification_text = (
            f"{mention_prefix}**{display_name}** {custom_message}\n"
            f"Watch at {twitch_url}"
        )

        # Build the fallback embed.
        embed = discord.Embed(
            title=f"{display_name} is LIVE!",
            description=f"{custom_message}\n\n[Watch on Twitch]({twitch_url})",
            color=discord.Color.purple(),
            url=twitch_url,
            timestamp=now,
        )
        if stream_title:
            embed.add_field(name="Stream Title", value=stream_title, inline=False)
        embed.set_footer(text="Twitch Live Notification")

        # --- Per-guild card render (use per-guild bg_path for the image) -----
        per_guild_card: Optional[bytes] = None
        if _CARDS_AVAILABLE and bg_path and bg_path != (guild_rows[0]["background_cache_path"] if guild_rows else None):
            # Different background from the one used for the shared render —
            # re-render for this guild.
            try:
                per_guild_card = await asyncio.to_thread(
                    render_card,
                    display_name,
                    stream_title,
                    bg_path,
                    avatar_bytes,
                    custom_message,
                )
            except Exception as exc:
                log.warning("go-live notify: per-guild re-render failed for guild %s: %s", guild_id, exc)

        # Decide which card bytes to use.
        use_card = per_guild_card or card_bytes

        try:
            if use_card:
                file = discord.File(
                    io.BytesIO(use_card),
                    filename=f"golive_{broadcaster_id}.png",
                )
                await dest.send(content=notification_text, file=file)
            else:
                # Plain embed fallback — never drop the notification.
                await dest.send(content=notification_text, embed=embed)

            log.info(
                "go-live notify: sent to #%s in guild %s (card=%s)",
                dest.name, guild_id, use_card is not None,
            )
        except discord.Forbidden:
            log.warning(
                "go-live notify: Forbidden posting to #%s in guild %s",
                dest.name, guild_id,
            )
        except discord.HTTPException as exc:
            log.warning(
                "go-live notify: HTTP error posting to #%s in guild %s: %s",
                dest.name, guild_id, exc,
            )


# --------------------------------------------------------------------------- #
# /help
# --------------------------------------------------------------------------- #

COMMAND_HELP = [
    ("/help", "[Admin] Show this command list."),
    (
        "/bulk-purge-user <user>",
        "[Admin] Ban the user, delete their messages from the last 14 days across all "
        "channels & threads, and remove any webhooks they created (plus those "
        "webhooks' messages).",
    ),
    (
        "/audit-permissions",
        "[Admin] Audit every role, @everyone, and all integrations/apps for dangerous "
        "permissions. Returns a colour-coded embed.",
    ),
    ("/purge-webhooks", "[Admin] Delete every webhook in the server to close spam backdoors."),
    (
        "/panic <lock|unlock>",
        "[Admin] lock freezes all text channels for @everyone (skipping already read-only "
        "ones); unlock restores them to their exact pre-lock state.",
    ),
    ("/wipe-invites", "[Admin] Delete all active invite links so banned users can't rejoin."),
    (
        "/trace-app <app>",
        "[Admin] Find the user(s) behind an app/bot — the integration installer and/or "
        "whoever invoked a user-installed app to post — so you can ban them.",
    ),
    (
        "/xp-config",
        "[Admin] Configure the per-guild XP/leveling system: enable/disable, "
        "XP range, cooldown, Twitch multiplier (default 2x), and level-up channel.",
    ),
    (
        "/twitch-setup <channel>",
        "[Server owner only] Begin the owner-consent handshake to link a Twitch channel. "
        "The bot posts a message in that Twitch chat asking the channel owner to type "
        "**!approve-xp** to confirm. Once approved, members who link their Twitch "
        "account via /twitch-link will earn Discord XP by chatting there. "
        "The request expires in 10 minutes.",
    ),
    (
        "/twitch-notify",
        "[Manage Server] Configure go-live card notifications: set the announcement "
        "channel, mention (@everyone or a role), a custom message, and an optional "
        "custom background image URL. When the linked Twitch channel goes live the bot "
        "posts a notification card in the chosen channel.",
    ),
    (
        "/rank-card-config <background_url>",
        "[Manage Server] Set a custom background image for /rank cards in this server. "
        "Supply any public HTTPS image URL (max 8 MB, 4096x4096 px). The image is "
        "validated and cached securely. Once set, /rank will render a 1200x400 card "
        "showing the member's avatar, level, rank, and XP progress bar.",
    ),
    (
        "/levelup-card-config",
        "[Manage Server] Configure per-server level-up banners: set the announcement "
        "channel, a custom congratulatory message (supports {mention} and {level} "
        "placeholders), and an optional background image URL. When a member crosses a "
        "level boundary (from Discord or Twitch chat XP) the bot posts a 1200x400 card "
        "with their avatar, display name, and the new level reached.",
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
    (
        "/twitch-link",
        "[All members] Generate a one-time code to link your Twitch account. "
        "Once linked, chatting in the server's Twitch channel earns you Discord XP "
        "while the stream is live.",
    ),
    (
        "/twitch-unlink",
        "[All members] Remove the link between your Discord and Twitch accounts.",
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
        "Commands marked **[Admin]** require the **Administrator** permission.\n"
        "Commands marked **[All members]** are open to everyone."
    )
    for name, desc in COMMAND_HELP:
        embed.add_field(name=name, value=desc, inline=False)
    embed.set_footer(
        text="Admin actions are logged to #mod-logs if that channel exists. "
        "XP view commands (/rank, /leaderboard) and Twitch linking are open to all members."
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
    twitch_multiplier="Multiplier for XP earned from Twitch chat (default 2.0 = double Discord).",
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
    twitch_multiplier: Optional[float] = None,
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
    eff_twitch_mult = (
        twitch_multiplier if twitch_multiplier is not None else cfg["twitch_multiplier"]
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
    if eff_twitch_mult < 1:
        errors.append("twitch_multiplier must be >= 1 (Twitch can't earn less than Discord).")
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
            (guild_id, enabled, xp_min, xp_max, cooldown_secs, level_up_channel_id,
             twitch_multiplier)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(guild_id) DO UPDATE SET
            enabled             = excluded.enabled,
            xp_min              = excluded.xp_min,
            xp_max              = excluded.xp_max,
            cooldown_secs       = excluded.cooldown_secs,
            level_up_channel_id = excluded.level_up_channel_id,
            twitch_multiplier   = excluded.twitch_multiplier
        """,
        (guild.id, eff_enabled, eff_xp_min, eff_xp_max, eff_cooldown, eff_channel_id,
         eff_twitch_mult),
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
    tw_min = round(eff_xp_min * eff_twitch_mult)
    tw_max = round(eff_xp_max * eff_twitch_mult)
    embed.add_field(name="Enabled", value="Yes" if eff_enabled else "No")
    embed.add_field(name="Discord XP / msg", value=f"{eff_xp_min}–{eff_xp_max}")
    embed.add_field(name="Cooldown", value=f"{eff_cooldown}s")
    embed.add_field(
        name="Twitch XP / msg",
        value=f"{tw_min}–{tw_max}  ({eff_twitch_mult:g}× Discord)",
    )
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

        # Always build the embed — it serves as the fallback when no card is available.
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

        # Attempt to render a rank card if a background is configured.
        card_file: Optional[discord.File] = None
        if _CARDS_AVAILABLE:
            async with db.execute(
                "SELECT rank_background_cache_path FROM guild_card_config WHERE guild_id = ?",
                (guild_id,),
            ) as cur:
                cfg_row = await cur.fetchone()
            rank_bg_path: Optional[str] = (
                cfg_row["rank_background_cache_path"] if cfg_row else None
            )

            if rank_bg_path:
                # Fetch the user's Discord avatar bytes for the card.
                avatar_bytes: Optional[bytes] = None
                if target.display_avatar:
                    try:
                        avatar_bytes = await target.display_avatar.read()
                    except Exception as exc:
                        log.debug("rank: could not fetch avatar for %s: %s", user_id, exc)

                try:
                    card_png = await asyncio.to_thread(
                        render_rank_card,
                        target.display_name,
                        level,
                        rank_pos,
                        total_members_with_xp,
                        xp_into_level,
                        xp_needed,
                        total_xp,
                        rank_bg_path,
                        avatar_bytes,
                    )
                    card_file = discord.File(
                        io.BytesIO(card_png),
                        filename=f"rank_{user_id}.png",
                    )
                except Exception as exc:
                    log.warning(
                        "rank: card render failed for user %s: %s; falling back to plain embed",
                        user_id, exc,
                    )
                    card_file = None

        if card_file is not None:
            await interaction.followup.send(file=card_file)
        else:
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
# Feature 8: Twitch integration — /twitch-setup (admin only)
# --------------------------------------------------------------------------- #


@bot.tree.command(
    name="twitch-setup",
    description="[Server owner only] Link a Twitch channel — channel owner must type !approve-xp in chat.",
)
@app_commands.describe(
    channel="The Twitch channel login name (e.g. 'shroud', NOT the URL)."
)
@app_commands.default_permissions(administrator=True)
@app_commands.checks.has_permissions(administrator=True)
async def twitch_setup(interaction: discord.Interaction, channel: str) -> None:
    guild = interaction.guild
    if guild is None:
        await interaction.response.send_message(
            "This command can only be used in a server.", ephemeral=True
        )
        return

    # Restrict to the Discord server owner only.
    if interaction.user.id != guild.owner_id:
        await interaction.response.send_message(
            "⛔ Only the server owner can link a Twitch channel.",
            ephemeral=True,
        )
        return

    db = bot.db
    if db is None:
        await interaction.response.send_message(
            "❌ Database is not ready yet. Please try again in a moment.", ephemeral=True
        )
        return

    if not twitch_enabled:
        await interaction.response.send_message(
            "⚠️ Twitch integration is not enabled on this bot (missing TWITCH_* env vars).",
            ephemeral=True,
        )
        return

    await interaction.response.defer(thinking=True, ephemeral=True)

    channel_login = channel.strip().lstrip("@").lower()

    # --- Step 1: Resolve channel → broadcaster_user_id via Helix API ----------
    broadcaster_id: Optional[int] = None
    if TWITCH_CLIENT_ID and _AIOHTTP_AVAILABLE:
        app_token = await _get_app_access_token()
        if app_token:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        "https://api.twitch.tv/helix/users",
                        params={"login": channel_login},
                        headers={
                            "Client-ID": TWITCH_CLIENT_ID,
                            "Authorization": f"Bearer {app_token}",
                        },
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            users = data.get("data", [])
                            if not users:
                                await interaction.followup.send(
                                    f"❌ Twitch channel `{channel_login}` not found. "
                                    "Check the spelling and try again.",
                                    ephemeral=True,
                                )
                                return
                            broadcaster_id = int(users[0]["id"])
                        else:
                            log.warning("Helix /users lookup failed: HTTP %s", resp.status)
                            await interaction.followup.send(
                                "⚠️ Could not verify the Twitch channel via Helix API "
                                f"(HTTP {resp.status}). Please try again later.",
                                ephemeral=True,
                            )
                            return
            except Exception as exc:
                log.warning("Helix channel lookup error: %s", exc)
                await interaction.followup.send(
                    "⚠️ Could not reach the Twitch API. Please try again later.",
                    ephemeral=True,
                )
                return
    else:
        # Twitch env vars missing — we can't do the handshake without them.
        await interaction.followup.send(
            "⚠️ Twitch credentials are not fully configured. "
            "The bot owner must set TWITCH_CLIENT_ID and TWITCH_CLIENT_SECRET.",
            ephemeral=True,
        )
        return

    # broadcaster_id is guaranteed non-None from here on.
    assert broadcaster_id is not None

    # --- Step 2: Upsert pending_twitch_setup with 10-minute expiry -----------
    now = utcnow()
    expires_at = now + timedelta(minutes=10)
    await db.execute(
        """
        INSERT INTO pending_twitch_setup
            (guild_id, twitch_channel, twitch_broadcaster_id,
             requested_by_id, requested_by_name, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(guild_id) DO UPDATE SET
            twitch_channel        = excluded.twitch_channel,
            twitch_broadcaster_id = excluded.twitch_broadcaster_id,
            requested_by_id       = excluded.requested_by_id,
            requested_by_name     = excluded.requested_by_name,
            created_at            = excluded.created_at,
            expires_at            = excluded.expires_at
        """,
        (
            guild.id,
            channel_login,
            broadcaster_id,
            interaction.user.id,
            str(interaction.user),
            now.isoformat(),
            expires_at.isoformat(),
        ),
    )
    await db.commit()

    # --- Step 3: Tell the live twitchio client to join the channel now --------
    if twitch_client is not None:
        try:
            tc = twitch_client  # type: ignore[assignment]
            existing = [ch.name.lower() for ch in tc.connected_channels]
            if channel_login not in existing:
                await tc.join_channels([channel_login])
                log.info("Twitch client joined channel '%s' for pending consent handshake", channel_login)
        except Exception as exc:
            log.warning("Failed to join Twitch channel '%s' at runtime: %s", channel_login, exc)

    # --- Step 4: Post the consent message in Twitch chat ----------------------
    chat_post_ok = False
    chat_post_error: Optional[str] = None
    if twitch_client is not None:
        try:
            tc = twitch_client  # type: ignore[assignment]
            # Find the channel object we just joined (or were already in).
            ch_obj = None
            for connected_ch in tc.connected_channels:
                if connected_ch.name.lower() == channel_login:
                    ch_obj = connected_ch
                    break
            if ch_obj is not None:
                consent_msg = (
                    f"[Bams Modmin Tools] The owner of Discord server '{guild.name}' "
                    f"(requested by {interaction.user}) wants to link THIS channel so "
                    f"chatters earn XP there. If you're the channel owner, type "
                    f"!approve-xp to confirm. Ignore to deny. (expires in 10 min)"
                )
                await ch_obj.send(consent_msg)
                chat_post_ok = True
                log.info("Consent message posted in Twitch channel '%s'", channel_login)
            else:
                chat_post_error = "Bot joined but could not resolve the channel object."
        except Exception as exc:
            chat_post_error = str(exc)
            log.warning("Failed to post consent message in '%s': %s", channel_login, exc)

    # --- Step 5: Reply to the Discord owner ----------------------------------
    if chat_post_ok:
        reply = (
            f"Request sent to Twitch channel **{channel_login}**.\n\n"
            f"The channel owner must type `!approve-xp` in their Twitch chat to approve "
            f"the link. The request expires in **10 minutes**.\n\n"
            f"Once approved, members who run `/twitch-link` will earn Discord XP by "
            f"chatting in that channel."
        )
    else:
        # Chat post failed — give the owner the fallback phrase.
        error_detail = f" ({chat_post_error})" if chat_post_error else ""
        reply = (
            f"⚠️ The bot couldn't post in **{channel_login}**'s Twitch chat{error_detail}.\n\n"
            f"You can still tell the channel owner to type `!approve-xp` in their chat — "
            f"the bot is listening and will approve the link when they do. "
            f"The request expires in **10 minutes**."
        )

    await interaction.followup.send(reply, ephemeral=True)

    # Mod-log the pending request.
    embed = discord.Embed(
        title="Twitch Channel Link Requested",
        description=(
            f"A consent request was sent to Twitch channel **{channel_login}**.\n"
            f"Waiting for the channel owner to type `!approve-xp` in chat."
        ),
        color=discord.Color.purple(),
        timestamp=utcnow(),
    )
    embed.add_field(name="Twitch Channel", value=channel_login)
    embed.add_field(name="Broadcaster ID", value=str(broadcaster_id))
    embed.add_field(name="Requested By", value=f"{interaction.user.mention} ({interaction.user})", inline=False)
    embed.add_field(name="Expires", value=expires_at.strftime("%Y-%m-%d %H:%M UTC"), inline=False)
    if not chat_post_ok:
        embed.add_field(
            name="Note",
            value="Bot could not post in Twitch chat; owner was given the fallback phrase.",
            inline=False,
        )
    embed.set_footer(text=f"Initiated by {interaction.user}")
    await send_mod_log(guild, embed)


# --------------------------------------------------------------------------- #
# Feature 8: Twitch integration — /twitch-link (all members)
# --------------------------------------------------------------------------- #


@bot.tree.command(
    name="twitch-link",
    description="Link your Twitch account to earn XP from Twitch chat (live streams only).",
)
async def twitch_link(interaction: discord.Interaction) -> None:
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

    discord_user_id = interaction.user.id

    # Check whether this guild has a Twitch channel configured.
    async with db.execute(
        "SELECT twitch_channel FROM guild_twitch_config WHERE guild_id = ?",
        (guild.id,),
    ) as cur:
        cfg_row = await cur.fetchone()

    if cfg_row is None or not cfg_row["twitch_channel"]:
        await interaction.followup.send(
            "⚠️ This server hasn't set up a Twitch channel yet. "
            "Ask an admin to run `/twitch-setup` first.",
            ephemeral=True,
        )
        return

    twitch_channel = cfg_row["twitch_channel"]

    # Check if the user already has a linked account (just informational).
    async with db.execute(
        "SELECT twitch_login FROM linked_accounts WHERE discord_user_id = ?",
        (discord_user_id,),
    ) as cur:
        existing_link = await cur.fetchone()

    already_linked_msg = ""
    if existing_link:
        already_linked_msg = (
            f"You currently have Twitch account **{existing_link['twitch_login']}** linked. "
            "Completing the steps below will re-link with the new account.\n\n"
        )

    # Generate a one-time code.
    code = secrets.token_hex(3).upper()  # 6 hex chars, e.g. "A3F7C2"
    now = utcnow()
    expires_at = now + timedelta(minutes=10)

    # Clean up any previous pending codes for this Discord user first.
    await db.execute(
        "DELETE FROM pending_link_codes WHERE discord_user_id = ?", (discord_user_id,)
    )
    await db.execute(
        """
        INSERT INTO pending_link_codes (code, discord_user_id, created_at, expires_at)
        VALUES (?, ?, ?, ?)
        """,
        (code, discord_user_id, now.isoformat(), expires_at.isoformat()),
    )
    await db.commit()

    instructions = (
        f"{already_linked_msg}"
        f"To link your Twitch account, type the following in the "
        f"**[{twitch_channel}](https://twitch.tv/{twitch_channel})** Twitch chat:\n\n"
        f"```\n!link {code}\n```\n"
        f"This code expires in **10 minutes**. Do not share it."
    )

    # Try to DM the user.
    dm_sent = False
    try:
        await interaction.user.send(
            f"**Bams Modmin Tools — Twitch Link**\n\n{instructions}"
        )
        dm_sent = True
    except discord.Forbidden:
        pass  # DMs closed — fall back to the ephemeral reply
    except discord.HTTPException as exc:
        log.warning("Failed to DM twitch-link code to %s: %s", discord_user_id, exc)

    if dm_sent:
        reply = (
            "Check your DMs for your link code and instructions!\n"
            f"_(If you didn't receive a DM, your code is: `{code}` — "
            f"type `!link {code}` in **{twitch_channel}** on Twitch.)_"
        )
    else:
        reply = (
            "**Your DMs appear to be closed**, so here are your instructions:\n\n"
            + instructions
        )

    await interaction.followup.send(reply, ephemeral=True)


# --------------------------------------------------------------------------- #
# Feature 8: Twitch integration — /twitch-unlink (all members)
# --------------------------------------------------------------------------- #


@bot.tree.command(
    name="twitch-unlink",
    description="Remove the link between your Discord and Twitch accounts.",
)
async def twitch_unlink(interaction: discord.Interaction) -> None:
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

    discord_user_id = interaction.user.id

    async with db.execute(
        "SELECT twitch_login FROM linked_accounts WHERE discord_user_id = ?",
        (discord_user_id,),
    ) as cur:
        row = await cur.fetchone()

    if row is None:
        await interaction.followup.send(
            "You don't have a linked Twitch account.", ephemeral=True
        )
        return

    twitch_login = row["twitch_login"]
    await db.execute(
        "DELETE FROM linked_accounts WHERE discord_user_id = ?", (discord_user_id,)
    )
    await db.commit()

    await interaction.followup.send(
        f"Your Twitch account **{twitch_login}** has been unlinked from your Discord account.",
        ephemeral=True,
    )


# --------------------------------------------------------------------------- #
# Feature 9: Twitch go-live card notifications — /twitch-notify
# --------------------------------------------------------------------------- #


@bot.tree.command(
    name="twitch-notify",
    description="Configure go-live card notifications for the linked Twitch channel.",
)
@app_commands.describe(
    announce_channel="Channel where go-live cards will be posted.",
    mention="Who to ping: 'everyone', a role mention, or 'none' (default).",
    custom_message="Short message shown on the card (default: 'is now LIVE on Twitch!').",
    background_url="HTTPS URL of an image to use as the card background (max 8 MB, 4096x4096).",
)
@app_commands.default_permissions(manage_guild=True)
@app_commands.checks.has_permissions(manage_guild=True)
async def twitch_notify(
    interaction: discord.Interaction,
    announce_channel: Optional[discord.TextChannel] = None,
    mention: Optional[str] = None,
    custom_message: Optional[str] = None,
    background_url: Optional[str] = None,
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

    # --- Load or create the current config row --------------------------------
    async with db.execute(
        "SELECT * FROM guild_card_config WHERE guild_id = ?", (guild.id,)
    ) as cur:
        cfg = await cur.fetchone()

    # Current effective values.
    eff_channel_id = cfg["announce_channel_id"] if cfg else None
    eff_mention = cfg["mention_setting"] if cfg else 0
    eff_message = cfg["custom_message"] if cfg else "is now LIVE on Twitch!"
    eff_bg_url = cfg["background_url"] if cfg else None
    eff_bg_path = cfg["background_cache_path"] if cfg else None

    # --- Process announce_channel --------------------------------------------
    if announce_channel is not None:
        eff_channel_id = announce_channel.id

    # --- Process mention ------------------------------------------------------
    if mention is not None:
        m = mention.strip().lower()
        if m in ("none", "off", "no", ""):
            eff_mention = 0
        elif m in ("everyone", "@everyone"):
            eff_mention = -1
        else:
            # Try to parse a role mention or ID.
            role_id: Optional[int] = None
            if m.startswith("<@&") and m.endswith(">"):
                try:
                    role_id = int(m[3:-1])
                except ValueError:
                    pass
            else:
                try:
                    role_id = int(m)
                except ValueError:
                    pass
            if role_id is not None:
                role_obj = guild.get_role(role_id)
                if role_obj is None:
                    await interaction.followup.send(
                        f"❌ Role ID `{role_id}` not found in this server.", ephemeral=True
                    )
                    return
                eff_mention = role_id
            else:
                await interaction.followup.send(
                    "❌ Unrecognised mention value. Use `none`, `everyone`, or a role mention/ID.",
                    ephemeral=True,
                )
                return

    # --- Process custom_message -----------------------------------------------
    if custom_message is not None:
        if len(custom_message) > 200:
            await interaction.followup.send(
                "❌ Custom message must be 200 characters or fewer.", ephemeral=True
            )
            return
        eff_message = custom_message

    # --- Process background_url -----------------------------------------------
    bg_error: Optional[str] = None
    if background_url is not None:
        if not _CARDS_AVAILABLE:
            await interaction.followup.send(
                "⚠️ The card system is not available (Pillow is not installed on this host). "
                "Ask the bot owner to run `pip install Pillow` in the bot's environment.",
                ephemeral=True,
            )
            return
        # Ingest and validate the URL with the full SSRF pipeline.
        try:
            cache_path = await ingest_image_url(
                background_url, guild.id, purpose="golive"
            )
            eff_bg_url = background_url
            eff_bg_path = str(cache_path)
        except ImageIntakeError as exc:
            await interaction.followup.send(
                f"❌ Background image rejected: {exc}\n\n"
                "Only public HTTPS image URLs are accepted (no private/LAN addresses, "
                "max 8 MB, max 4096x4096 px).",
                ephemeral=True,
            )
            return
        except Exception as exc:
            log.warning("twitch-notify: unexpected image intake error: %s", exc)
            await interaction.followup.send(
                f"❌ Unexpected error processing image URL: {exc}", ephemeral=True
            )
            return

    # --- Upsert guild_card_config --------------------------------------------
    now_iso = utcnow().isoformat()
    await db.execute(
        """
        INSERT INTO guild_card_config
            (guild_id, announce_channel_id, mention_setting, custom_message,
             background_url, background_cache_path, background_cached_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(guild_id) DO UPDATE SET
            announce_channel_id   = COALESCE(excluded.announce_channel_id,   announce_channel_id),
            mention_setting       = excluded.mention_setting,
            custom_message        = excluded.custom_message,
            background_url        = COALESCE(excluded.background_url,        background_url),
            background_cache_path = COALESCE(excluded.background_cache_path, background_cache_path),
            background_cached_at  = CASE
                WHEN excluded.background_cache_path IS NOT NULL
                THEN excluded.background_cached_at
                ELSE background_cached_at
            END
        """,
        (
            guild.id,
            eff_channel_id,
            eff_mention,
            eff_message,
            eff_bg_url if background_url is not None else None,
            eff_bg_path if background_url is not None else None,
            now_iso if background_url is not None else None,
        ),
    )
    await db.commit()

    # --- Build confirmation embed --------------------------------------------
    channel_display = f"<#{eff_channel_id}>" if eff_channel_id else "*(not set)*"
    if eff_mention == 0:
        mention_display = "none"
    elif eff_mention == -1:
        mention_display = "@everyone"
    else:
        r = guild.get_role(eff_mention)
        mention_display = r.mention if r else f"<@&{eff_mention}>"

    bg_display = "*(not set)*"
    if background_url is not None and eff_bg_path:
        bg_display = f"Cached from: `{background_url[:80]}{'...' if len(background_url) > 80 else ''}`"
    elif eff_bg_url:
        bg_display = f"`{eff_bg_url[:80]}{'...' if len(eff_bg_url) > 80 else ''}`"

    embed = discord.Embed(
        title="Twitch Go-Live Notification Config",
        color=discord.Color.purple(),
        timestamp=utcnow(),
    )
    embed.add_field(name="Announcement Channel", value=channel_display, inline=False)
    embed.add_field(name="Mention / Ping", value=mention_display)
    embed.add_field(name="Custom Message", value=f'"{eff_message}"', inline=False)
    embed.add_field(name="Background Image", value=bg_display, inline=False)
    if not _CARDS_AVAILABLE:
        embed.add_field(
            name="Note",
            value="Pillow is not installed — notifications will use plain embeds only.",
            inline=False,
        )
    embed.set_footer(text=f"Configured by {interaction.user}")

    await interaction.followup.send(embed=embed, ephemeral=True)

    # Audit log.
    log_embed = discord.Embed(
        title="Twitch Notify Config Updated",
        description=f"{interaction.user.mention} updated go-live notification settings.",
        color=discord.Color.purple(),
        timestamp=utcnow(),
    )
    log_embed.add_field(name="Channel", value=channel_display)
    log_embed.add_field(name="Mention", value=mention_display)
    log_embed.add_field(name="Message", value=f'"{eff_message}"')
    log_embed.add_field(name="Background", value=bg_display, inline=False)
    log_embed.set_footer(text=f"Action by {interaction.user}")
    await send_mod_log(guild, log_embed)


# --------------------------------------------------------------------------- #
# Feature 9b: Rank-card background config — /rank-card-config (manage_guild)
# --------------------------------------------------------------------------- #
#
# Design choice: a dedicated sibling command rather than adding a parameter to
# /twitch-notify.  /twitch-notify is already Twitch-specific and has four params;
# folding rank-card config into it would make the command surface confusing.
# /rank-card-config is always available regardless of whether Twitch integration
# is enabled, which is cleaner for Discord-only deployments.


@bot.tree.command(
    name="rank-card-config",
    description="Set a custom background image for /rank cards in this server.",
)
@app_commands.describe(
    background_url="HTTPS URL of an image to use as the rank-card background (max 8 MB, 4096x4096).",
)
@app_commands.default_permissions(manage_guild=True)
@app_commands.checks.has_permissions(manage_guild=True)
async def rank_card_config(
    interaction: discord.Interaction,
    background_url: str,
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

    if not _CARDS_AVAILABLE:
        await interaction.response.send_message(
            "⚠️ The card system is not available (Pillow is not installed on this host). "
            "Ask the bot owner to run `pip install Pillow` in the bot's environment.",
            ephemeral=True,
        )
        return

    await interaction.response.defer(thinking=True, ephemeral=True)

    # Ingest and validate the URL through the full SSRF pipeline.
    # Use purpose="rank" so rank backgrounds cache separately from go-live ones.
    try:
        cache_path = await ingest_image_url(background_url, guild.id, purpose="rank")
    except ImageIntakeError as exc:
        await interaction.followup.send(
            f"❌ Background image rejected: {exc}\n\n"
            "Only public HTTPS image URLs are accepted (no private/LAN addresses, "
            "max 8 MB, max 4096x4096 px).",
            ephemeral=True,
        )
        return
    except Exception as exc:
        log.warning("rank-card-config: unexpected image intake error: %s", exc)
        await interaction.followup.send(
            f"❌ Unexpected error processing image URL: {exc}", ephemeral=True
        )
        return

    now_iso = utcnow().isoformat()
    bg_path_str = str(cache_path)

    # Upsert guild_card_config, touching only the rank background columns.
    await db.execute(
        """
        INSERT INTO guild_card_config
            (guild_id, mention_setting, custom_message,
             rank_background_url, rank_background_cache_path, rank_background_cached_at)
        VALUES (?, 0, 'is now LIVE on Twitch!', ?, ?, ?)
        ON CONFLICT(guild_id) DO UPDATE SET
            rank_background_url        = excluded.rank_background_url,
            rank_background_cache_path = excluded.rank_background_cache_path,
            rank_background_cached_at  = excluded.rank_background_cached_at
        """,
        (guild.id, background_url, bg_path_str, now_iso),
    )
    await db.commit()

    url_display = f"`{background_url[:80]}{'...' if len(background_url) > 80 else ''}`"

    embed = discord.Embed(
        title="Rank Card Background Updated",
        description=(
            f"The rank-card background for **{guild.name}** has been updated.\n"
            f"Members will see the new background when they use `/rank`."
        ),
        color=discord.Color.blurple(),
        timestamp=utcnow(),
    )
    embed.add_field(name="Background Image", value=url_display, inline=False)
    embed.add_field(name="Cache Path", value=f"`{bg_path_str}`", inline=False)
    embed.set_footer(text=f"Configured by {interaction.user}")

    await interaction.followup.send(embed=embed, ephemeral=True)

    # Audit log.
    log_embed = discord.Embed(
        title="Rank Card Config Updated",
        description=f"{interaction.user.mention} set the rank-card background.",
        color=discord.Color.blurple(),
        timestamp=utcnow(),
    )
    log_embed.add_field(name="Background", value=url_display, inline=False)
    log_embed.set_footer(text=f"Action by {interaction.user}")
    await send_mod_log(guild, log_embed)


# --------------------------------------------------------------------------- #
# Feature 9c: Level-up banner config — /levelup-card-config (manage_guild)
# --------------------------------------------------------------------------- #
#
# Design choice: a dedicated sibling command rather than extending /twitch-notify
# or /rank-card-config.  Level-up banners are independent of Twitch integration
# (they fire on both Discord and Twitch XP paths) and have their own announce
# channel, message template, and background, so folding them into either existing
# command would make those commands confusing.  /levelup-card-config is always
# available regardless of whether Twitch is enabled.


@bot.tree.command(
    name="levelup-card-config",
    description="Configure level-up banners: channel, custom message, and background image.",
)
@app_commands.describe(
    announce_channel="Channel where level-up banners will be posted.",
    custom_message=(
        "Congratulatory message shown on the banner (use {mention} and {level} as "
        "placeholders, max 200 chars). Default: '{mention} just levelled up!'"
    ),
    background_url="HTTPS URL of an image to use as the banner background (max 8 MB, 4096x4096).",
)
@app_commands.default_permissions(manage_guild=True)
@app_commands.checks.has_permissions(manage_guild=True)
async def levelup_card_config(
    interaction: discord.Interaction,
    announce_channel: Optional[discord.TextChannel] = None,
    custom_message: Optional[str] = None,
    background_url: Optional[str] = None,
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

    # --- Load current config (if any) ----------------------------------------
    async with db.execute(
        "SELECT levelup_announce_channel_id, levelup_background_url, "
        "       levelup_background_cache_path, levelup_message "
        "FROM guild_card_config WHERE guild_id = ?",
        (guild.id,),
    ) as cur:
        cfg = await cur.fetchone()

    eff_channel_id: Optional[int] = cfg["levelup_announce_channel_id"] if cfg else None
    eff_bg_url: Optional[str] = cfg["levelup_background_url"] if cfg else None
    eff_bg_path: Optional[str] = cfg["levelup_background_cache_path"] if cfg else None
    eff_message: str = (
        (cfg["levelup_message"] if cfg and cfg["levelup_message"] else None)
        or "{mention} just levelled up!"
    )

    # --- Process announce_channel --------------------------------------------
    if announce_channel is not None:
        eff_channel_id = announce_channel.id

    # --- Process custom_message ----------------------------------------------
    if custom_message is not None:
        if len(custom_message) > 200:
            await interaction.followup.send(
                "❌ Custom message must be 200 characters or fewer.", ephemeral=True
            )
            return
        eff_message = custom_message

    # --- Process background_url ----------------------------------------------
    if background_url is not None:
        if not _CARDS_AVAILABLE:
            await interaction.followup.send(
                "⚠️ The card system is not available (Pillow is not installed on this host). "
                "Ask the bot owner to run `pip install Pillow` in the bot's environment.",
                ephemeral=True,
            )
            return
        try:
            cache_path = await ingest_image_url(
                background_url, guild.id, purpose="levelup"
            )
            eff_bg_url = background_url
            eff_bg_path = str(cache_path)
        except ImageIntakeError as exc:
            await interaction.followup.send(
                f"❌ Background image rejected: {exc}\n\n"
                "Only public HTTPS image URLs are accepted (no private/LAN addresses, "
                "max 8 MB, max 4096x4096 px).",
                ephemeral=True,
            )
            return
        except Exception as exc:
            log.warning("levelup-card-config: unexpected image intake error: %s", exc)
            await interaction.followup.send(
                f"❌ Unexpected error processing image URL: {exc}", ephemeral=True
            )
            return

    # --- Upsert guild_card_config — touch only levelup columns ---------------
    now_iso = utcnow().isoformat()
    await db.execute(
        """
        INSERT INTO guild_card_config
            (guild_id, mention_setting, custom_message,
             levelup_announce_channel_id, levelup_message,
             levelup_background_url, levelup_background_cache_path,
             levelup_background_cached_at)
        VALUES (?, 0, 'is now LIVE on Twitch!', ?, ?, ?, ?, ?)
        ON CONFLICT(guild_id) DO UPDATE SET
            levelup_announce_channel_id   =
                COALESCE(excluded.levelup_announce_channel_id,
                         levelup_announce_channel_id),
            levelup_message               = excluded.levelup_message,
            levelup_background_url        =
                COALESCE(excluded.levelup_background_url,        levelup_background_url),
            levelup_background_cache_path =
                COALESCE(excluded.levelup_background_cache_path, levelup_background_cache_path),
            levelup_background_cached_at  =
                CASE
                    WHEN excluded.levelup_background_cache_path IS NOT NULL
                    THEN excluded.levelup_background_cached_at
                    ELSE levelup_background_cached_at
                END
        """,
        (
            guild.id,
            eff_channel_id,
            eff_message,
            eff_bg_url if background_url is not None else None,
            eff_bg_path if background_url is not None else None,
            now_iso if background_url is not None else None,
        ),
    )
    await db.commit()

    # --- Build confirmation embed --------------------------------------------
    channel_display = f"<#{eff_channel_id}>" if eff_channel_id else "*(not set)*"
    bg_display = "*(not set)*"
    if background_url is not None and eff_bg_path:
        bg_display = f"Cached from: `{background_url[:80]}{'...' if len(background_url) > 80 else ''}`"
    elif eff_bg_url:
        bg_display = f"`{eff_bg_url[:80]}{'...' if len(eff_bg_url) > 80 else ''}`"

    embed = discord.Embed(
        title="Level-Up Banner Config",
        color=discord.Color.gold(),
        timestamp=utcnow(),
    )
    embed.add_field(name="Announcement Channel", value=channel_display, inline=False)
    embed.add_field(name="Custom Message", value=f'"{eff_message}"', inline=False)
    embed.add_field(name="Background Image", value=bg_display, inline=False)
    embed.add_field(
        name="Placeholders",
        value="`{mention}` — pings the member  |  `{level}` — the level reached",
        inline=False,
    )
    if not _CARDS_AVAILABLE:
        embed.add_field(
            name="Note",
            value="Pillow is not installed — banners will use plain embeds only.",
            inline=False,
        )
    embed.set_footer(text=f"Configured by {interaction.user}")

    await interaction.followup.send(embed=embed, ephemeral=True)

    # --- Audit log -----------------------------------------------------------
    log_embed = discord.Embed(
        title="Level-Up Banner Config Updated",
        description=f"{interaction.user.mention} updated level-up banner settings.",
        color=discord.Color.gold(),
        timestamp=utcnow(),
    )
    log_embed.add_field(name="Channel", value=channel_display)
    log_embed.add_field(name="Message", value=f'"{eff_message}"', inline=False)
    log_embed.add_field(name="Background", value=bg_display, inline=False)
    log_embed.set_footer(text=f"Action by {interaction.user}")
    await send_mod_log(guild, log_embed)


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
# Entry point — async main running Discord + Twitch concurrently
# --------------------------------------------------------------------------- #


async def main() -> None:
    if not BOT_TOKEN:
        raise SystemExit("BOT_TOKEN is not set. Copy .env.example to .env and add your token.")

    if not twitch_enabled:
        if not _TWITCHIO_AVAILABLE:
            log.info("Twitch integration disabled (twitchio not installed)")
        else:
            log.info("Twitch integration disabled (missing config: "
                     "need TWITCH_CLIENT_ID, TWITCH_CLIENT_SECRET, TWITCH_BOT_USERNAME, "
                     "TWITCH_BOT_ACCESS_TOKEN, TWITCH_BOT_REFRESH_TOKEN)")

    # Run the Discord bot. The Twitch client (if enabled) is started as a
    # background task from on_ready, after setup_hook has opened the DB.
    async with bot:
        await bot.start(BOT_TOKEN)


if __name__ == "__main__":
    asyncio.run(main())
