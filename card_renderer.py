"""
card_renderer.py — Pillow-based card compositor.

Produces 1200x400 PNG cards:

  render_card() — go-live notification card with:
    • A full-bleed background image (or a solid fallback gradient).
    • A semi-transparent dark overlay so text is always legible.
    • Circular avatar in the top-left area.
    • Broadcaster display name (bold, large).
    • Stream title (regular, smaller, truncated).
    • A "LIVE" badge.
    • All text with a drop-shadow / outline for legibility over any background.

  render_rank_card() — XP rank card with:
    • A full-bleed background image (or a solid dark fallback).
    • A semi-transparent dark overlay for legibility.
    • Circular user avatar (left side).
    • Display name (bold, large, truncated).
    • Level badge.
    • Server rank position.
    • XP progress bar (current/next XP text alongside).
    • All text with shadow/outline.

Fonts: NotoSans-Regular and NotoSans-Bold from assets/fonts/ (OFL 1.1 license).
These must be present; if not, falls back to Pillow's default bitmap font
(legibility is reduced but the card still renders).

IMPORTANT: render_card() and render_rank_card() must always be called from
outside the event loop via asyncio.to_thread(...) because Pillow is CPU-bound
and synchronous.
"""

from __future__ import annotations

import io
import logging
import os
from pathlib import Path
from typing import Optional

log = logging.getLogger("modmin-tools.card_renderer")

# --------------------------------------------------------------------------- #
# Card layout constants
# --------------------------------------------------------------------------- #

CARD_W: int = 1200
CARD_H: int = 400
AVATAR_SIZE: int = 150      # diameter of circular avatar
AVATAR_X: int = 50          # left edge of avatar
AVATAR_Y: int = 125         # top edge of avatar (centres vertically)
TEXT_X: int = 230           # start of text block (after avatar)
FONT_DIR: Path = Path(__file__).parent / "assets" / "fonts"


def _load_fonts(size_large: int = 60, size_small: int = 32) -> tuple:
    """Load NotoSans-Bold and NotoSans-Regular, falling back to default."""
    try:
        from PIL import ImageFont
        bold_path = FONT_DIR / "NotoSans-Bold.ttf"
        reg_path = FONT_DIR / "NotoSans-Regular.ttf"
        if bold_path.exists() and reg_path.exists():
            font_large = ImageFont.truetype(str(bold_path), size_large)
            font_small = ImageFont.truetype(str(reg_path), size_small)
            font_badge = ImageFont.truetype(str(bold_path), 26)
            log.debug("card_renderer: loaded NotoSans fonts")
            return font_large, font_small, font_badge
    except Exception as exc:
        log.warning("card_renderer: could not load TrueType fonts: %s", exc)

    # Fallback — Pillow built-in bitmap font (very small, no size parameter).
    from PIL import ImageFont
    fallback = ImageFont.load_default()
    return fallback, fallback, fallback


def _draw_text_with_shadow(
    draw,
    pos: tuple[int, int],
    text: str,
    font,
    fill: tuple[int, int, int, int] = (255, 255, 255, 255),
    shadow: tuple[int, int, int, int] = (0, 0, 0, 200),
    shadow_offset: int = 3,
) -> None:
    """Draw text with a drop-shadow for legibility over arbitrary backgrounds."""
    x, y = pos
    # Shadow pass.
    draw.text((x + shadow_offset, y + shadow_offset), text, font=font, fill=shadow)
    # Main text.
    draw.text((x, y), text, font=font, fill=fill)


def _draw_outline_text(
    draw,
    pos: tuple[int, int],
    text: str,
    font,
    fill: tuple[int, int, int, int] = (255, 255, 255, 255),
    outline: tuple[int, int, int, int] = (0, 0, 0, 255),
    thickness: int = 2,
) -> None:
    """Draw text with a pixel-outline for maximum legibility."""
    x, y = pos
    for dx in range(-thickness, thickness + 1):
        for dy in range(-thickness, thickness + 1):
            if dx == 0 and dy == 0:
                continue
            draw.text((x + dx, y + dy), text, font=font, fill=outline)
    draw.text((x, y), text, font=font, fill=fill)


def _truncate_text(text: str, font, max_width: int, draw) -> str:
    """Truncate `text` so that it fits within max_width pixels, appending '…'."""
    if not text:
        return text
    # getbbox may not be available on default bitmap font.
    try:
        bbox = draw.textbbox((0, 0), text, font=font)
        text_w = bbox[2] - bbox[0]
    except Exception:
        return text

    if text_w <= max_width:
        return text

    while len(text) > 1:
        text = text[:-1]
        try:
            bbox = draw.textbbox((0, 0), text + "…", font=font)
            w = bbox[2] - bbox[0]
        except Exception:
            break
        if w <= max_width:
            return text + "…"

    return text + "…"


def _circular_mask(size: int):
    """Return an RGBA image that is white inside a circle, transparent outside."""
    from PIL import Image, ImageDraw
    mask = Image.new("L", (size, size), 0)
    draw = ImageDraw.Draw(mask)
    draw.ellipse((0, 0, size - 1, size - 1), fill=255)
    return mask


def render_card(
    broadcaster_name: str,
    stream_title: str,
    background_path: Optional[str],
    avatar_bytes: Optional[bytes],
    custom_message: str = "is now LIVE on Twitch!",
) -> bytes:
    """Composite a go-live card and return PNG bytes.

    Parameters
    ----------
    broadcaster_name : str
        The Twitch display name of the broadcaster.
    stream_title : str
        The current stream title (may be empty).
    background_path : str | None
        Path to a cached background image (from image_intake).
        If None or invalid, a solid-colour fallback is used.
    avatar_bytes : bytes | None
        Raw image bytes for the broadcaster avatar (fetched separately from Twitch).
        If None, a placeholder circle is drawn instead.
    custom_message : str
        Short line shown below the name (configurable per-guild).

    Returns
    -------
    bytes
        Raw PNG bytes ready to be uploaded as a Discord attachment.
    """
    from PIL import Image, ImageDraw

    # ---- 1. Background -------------------------------------------------------
    # Delegate to the shared scale-to-cover helper so the logic lives once.
    bg = _bg_from_path(background_path)

    # ---- 2. Dark overlay for legibility -------------------------------------
    overlay = Image.new("RGBA", (CARD_W, CARD_H), (0, 0, 0, 0))
    overlay_draw = ImageDraw.Draw(overlay)
    overlay_draw.rectangle([(0, 0), (CARD_W, CARD_H)], fill=(0, 0, 0, 140))
    bg = Image.alpha_composite(bg, overlay)

    # ---- 3. Avatar -----------------------------------------------------------
    if avatar_bytes:
        try:
            import io as _io
            av_img = Image.open(_io.BytesIO(avatar_bytes)).convert("RGBA")
            av_img = av_img.resize((AVATAR_SIZE, AVATAR_SIZE), Image.LANCZOS)
            mask = _circular_mask(AVATAR_SIZE)
            # Transparent base; paste avatar through circle mask.
            av_base = Image.new("RGBA", (AVATAR_SIZE, AVATAR_SIZE), (0, 0, 0, 0))
            av_base.paste(av_img, mask=mask)
            # Thin white border ring.
            ring = Image.new("RGBA", (AVATAR_SIZE + 8, AVATAR_SIZE + 8), (0, 0, 0, 0))
            ring_draw = ImageDraw.Draw(ring)
            ring_draw.ellipse((0, 0, AVATAR_SIZE + 7, AVATAR_SIZE + 7), fill=(255, 255, 255, 220))
            bg.paste(ring, (AVATAR_X - 4, AVATAR_Y - 4), ring)
            bg.paste(av_base, (AVATAR_X, AVATAR_Y), av_base)
        except Exception as exc:
            log.warning("card_renderer: avatar render failed: %s", exc)
            _draw_placeholder_avatar(bg)
    else:
        _draw_placeholder_avatar(bg)

    # ---- 4. Text -------------------------------------------------------------
    draw = ImageDraw.Draw(bg)
    font_large, font_small, font_badge = _load_fonts()

    # Available text width (from TEXT_X to near right edge).
    max_text_w = CARD_W - TEXT_X - 40

    # Broadcaster name (bold).
    name_text = _truncate_text(broadcaster_name or "Streamer", font_large, max_text_w, draw)
    _draw_outline_text(draw, (TEXT_X, 80), name_text, font_large, thickness=2)

    # Custom message / tagline.
    msg_text = _truncate_text(custom_message, font_small, max_text_w, draw)
    _draw_text_with_shadow(draw, (TEXT_X, 160), msg_text, font_small,
                           fill=(220, 220, 220, 255))

    # Stream title.
    if stream_title:
        title_text = _truncate_text(stream_title, font_small, max_text_w, draw)
        _draw_text_with_shadow(draw, (TEXT_X, 210), f'"{title_text}"', font_small,
                               fill=(200, 200, 200, 255))

    # ---- 5. LIVE badge -------------------------------------------------------
    badge_x, badge_y = CARD_W - 120, 20
    draw.rounded_rectangle(
        [(badge_x, badge_y), (badge_x + 90, badge_y + 38)],
        radius=8,
        fill=(235, 64, 52, 230),  # Twitch-ish red
    )
    _draw_text_with_shadow(draw, (badge_x + 14, badge_y + 6), "LIVE", font_badge,
                           fill=(255, 255, 255, 255), shadow=(0, 0, 0, 120),
                           shadow_offset=2)

    # ---- 6. Encode as PNG ----------------------------------------------------
    buf = io.BytesIO()
    bg.convert("RGB").save(buf, format="PNG", optimize=True)
    buf.seek(0)
    return buf.read()


def _solid_bg() -> "Image.Image":  # type: ignore[return]
    """Return a solid dark-purple gradient background as an RGBA Image."""
    from PIL import Image, ImageDraw
    img = Image.new("RGBA", (CARD_W, CARD_H), (30, 20, 50, 255))
    draw = ImageDraw.Draw(img)
    # Simple horizontal gradient via bands.
    for x in range(CARD_W):
        r = int(30 + (x / CARD_W) * 20)
        g = int(20 + (x / CARD_W) * 10)
        b = int(50 + (x / CARD_W) * 40)
        draw.line([(x, 0), (x, CARD_H)], fill=(r, g, b, 255))
    return img


def _draw_placeholder_avatar(bg: "Image.Image") -> None:
    """Draw a plain circular placeholder where the avatar would be."""
    from PIL import ImageDraw
    draw = ImageDraw.Draw(bg)
    draw.ellipse(
        [(AVATAR_X, AVATAR_Y), (AVATAR_X + AVATAR_SIZE, AVATAR_Y + AVATAR_SIZE)],
        fill=(80, 60, 110, 200),
        outline=(255, 255, 255, 180),
        width=4,
    )


def _bg_from_path(background_path: Optional[str]) -> "Image.Image":
    """Open a background image and scale-to-cover/center-crop to CARD_W x CARD_H.

    Falls back to _solid_bg() if the path is None, missing, or unreadable.
    Shared by render_card() and render_rank_card() so the logic is in one place.
    """
    from PIL import Image
    if background_path and os.path.exists(background_path):
        try:
            bg = Image.open(background_path).convert("RGBA")
            src_w, src_h = bg.size
            scale = max(CARD_W / src_w, CARD_H / src_h)
            scaled_w = int(src_w * scale)
            scaled_h = int(src_h * scale)
            bg = bg.resize((scaled_w, scaled_h), Image.LANCZOS)
            left = (scaled_w - CARD_W) // 2
            top = (scaled_h - CARD_H) // 2
            bg = bg.crop((left, top, left + CARD_W, top + CARD_H))
            return bg
        except Exception as exc:
            log.warning("card_renderer: could not open background '%s': %s", background_path, exc)
    return _solid_bg()


# --------------------------------------------------------------------------- #
# Rank-card layout constants
# --------------------------------------------------------------------------- #

RANK_AVATAR_SIZE: int = 160      # slightly larger than go-live avatar
RANK_AVATAR_X: int = 40
RANK_AVATAR_Y: int = 120         # centres vertically in 400px card
RANK_TEXT_X: int = 230           # text block starts after avatar

# Progress bar geometry (sits in the lower third of the card)
BAR_X: int = 230
BAR_Y: int = 300
BAR_W: int = 880     # bar fills most of the remaining width
BAR_H: int = 28
BAR_RADIUS: int = 14


def render_rank_card(
    display_name: str,
    level: int,
    rank_pos: int,
    total_members: int,
    xp_into_level: int,
    xp_needed: int,
    total_xp: int,
    background_path: Optional[str],
    avatar_bytes: Optional[bytes],
) -> bytes:
    """Composite a rank card and return PNG bytes.

    Parameters
    ----------
    display_name : str
        The member's display name (truncated if needed).
    level : int
        The member's current level.
    rank_pos : int
        The member's position in the server leaderboard (1 = top).
    total_members : int
        Total number of members with XP data (for the "X of Y" display).
    xp_into_level : int
        XP earned within the current level (progress toward next level).
    xp_needed : int
        Total XP required to advance from current level to next level.
    total_xp : int
        Cumulative XP across all levels.
    background_path : str | None
        Path to a cached background image (from image_intake, purpose="rank").
        If None or invalid, a solid-colour fallback is used.
    avatar_bytes : bytes | None
        Raw image bytes for the user's Discord avatar.
        If None, a placeholder circle is drawn instead.

    Returns
    -------
    bytes
        Raw PNG bytes ready to be uploaded as a Discord attachment.
    """
    from PIL import Image, ImageDraw

    # ---- 1. Background -------------------------------------------------------
    bg = _bg_from_path(background_path)

    # ---- 2. Dark overlay for legibility -------------------------------------
    overlay = Image.new("RGBA", (CARD_W, CARD_H), (0, 0, 0, 0))
    overlay_draw = ImageDraw.Draw(overlay)
    overlay_draw.rectangle([(0, 0), (CARD_W, CARD_H)], fill=(0, 0, 0, 155))
    bg = Image.alpha_composite(bg, overlay)

    # ---- 3. Avatar -----------------------------------------------------------
    if avatar_bytes:
        try:
            import io as _io
            av_img = Image.open(_io.BytesIO(avatar_bytes)).convert("RGBA")
            av_img = av_img.resize((RANK_AVATAR_SIZE, RANK_AVATAR_SIZE), Image.LANCZOS)
            mask = _circular_mask(RANK_AVATAR_SIZE)
            av_base = Image.new("RGBA", (RANK_AVATAR_SIZE, RANK_AVATAR_SIZE), (0, 0, 0, 0))
            av_base.paste(av_img, mask=mask)
            # White border ring.
            ring = Image.new("RGBA", (RANK_AVATAR_SIZE + 8, RANK_AVATAR_SIZE + 8), (0, 0, 0, 0))
            ring_draw = ImageDraw.Draw(ring)
            ring_draw.ellipse(
                (0, 0, RANK_AVATAR_SIZE + 7, RANK_AVATAR_SIZE + 7),
                fill=(255, 255, 255, 220),
            )
            bg.paste(ring, (RANK_AVATAR_X - 4, RANK_AVATAR_Y - 4), ring)
            bg.paste(av_base, (RANK_AVATAR_X, RANK_AVATAR_Y), av_base)
        except Exception as exc:
            log.warning("card_renderer: rank avatar render failed: %s", exc)
            _draw_rank_placeholder_avatar(bg)
    else:
        _draw_rank_placeholder_avatar(bg)

    # ---- 4. Text block -------------------------------------------------------
    draw = ImageDraw.Draw(bg)
    font_large, font_small, font_badge = _load_fonts(size_large=54, size_small=28)

    max_text_w = CARD_W - RANK_TEXT_X - 40

    # Display name (bold, large).
    name_text = _truncate_text(display_name or "Member", font_large, max_text_w, draw)
    _draw_outline_text(draw, (RANK_TEXT_X, 60), name_text, font_large, thickness=2)

    # Level label.
    level_text = f"Level {level}"
    _draw_text_with_shadow(
        draw, (RANK_TEXT_X, 130), level_text, font_small,
        fill=(230, 230, 255, 255),
    )

    # Rank label.
    rank_text = f"Rank #{rank_pos} of {total_members}"
    _draw_text_with_shadow(
        draw, (RANK_TEXT_X, 168), rank_text, font_small,
        fill=(200, 220, 200, 255),
    )

    # Total XP label.
    xp_text = f"Total XP: {total_xp:,}"
    _draw_text_with_shadow(
        draw, (RANK_TEXT_X, 210), xp_text, font_small,
        fill=(210, 210, 210, 255),
    )

    # ---- 5. XP progress bar --------------------------------------------------
    # Background track.
    draw.rounded_rectangle(
        [(BAR_X, BAR_Y), (BAR_X + BAR_W, BAR_Y + BAR_H)],
        radius=BAR_RADIUS,
        fill=(60, 60, 60, 200),
    )

    # Filled portion.
    if xp_needed > 0:
        fill_ratio = max(0.0, min(1.0, xp_into_level / xp_needed))
    else:
        fill_ratio = 1.0
    fill_w = max(BAR_RADIUS * 2, int(BAR_W * fill_ratio))  # keep ends round

    draw.rounded_rectangle(
        [(BAR_X, BAR_Y), (BAR_X + fill_w, BAR_Y + BAR_H)],
        radius=BAR_RADIUS,
        fill=(100, 160, 255, 230),   # accent blue
    )

    # Progress label below the bar.
    progress_label = f"{xp_into_level:,} / {xp_needed:,} XP to level {level + 1}"
    _draw_text_with_shadow(
        draw, (BAR_X, BAR_Y + BAR_H + 6), progress_label, font_small,
        fill=(210, 220, 255, 255),
    )

    # ---- 6. Encode as PNG ----------------------------------------------------
    buf = io.BytesIO()
    bg.convert("RGB").save(buf, format="PNG", optimize=True)
    buf.seek(0)
    return buf.read()


def _draw_rank_placeholder_avatar(bg: "Image.Image") -> None:
    """Draw a plain circular placeholder for the rank-card avatar."""
    from PIL import ImageDraw
    draw = ImageDraw.Draw(bg)
    draw.ellipse(
        [
            (RANK_AVATAR_X, RANK_AVATAR_Y),
            (RANK_AVATAR_X + RANK_AVATAR_SIZE, RANK_AVATAR_Y + RANK_AVATAR_SIZE),
        ],
        fill=(60, 60, 100, 200),
        outline=(255, 255, 255, 180),
        width=4,
    )
