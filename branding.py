"""
branding.py
-----------
Generates a simple corporate-style header banner image for each client
organization, used at the top of every simulation email.

Why generate this ourselves instead of letting the admin upload a real
logo file? For the MVP, generating it server-side means:
  - No file upload/storage handling needed (smaller attack surface)
  - No risk of an admin accidentally uploading something inappropriate
    or copyrighted into an email that then gets sent out
  - Zero extra dependencies beyond Pillow, which is already common

This is a reasonable placeholder for the real feature (a proper logo
upload) that a production version would add later — worth noting as a
scoping decision in the thesis, same as the CSV-vs-AD-sync point.
"""

import io
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont
from flask import Blueprint, send_file

from database import get_db

branding_bp = Blueprint("branding", __name__)

# Mirrors admin.py's STATIC_DIR/LOGO_DIR — same folder, same filename
# convention ("org_<id>.png"), set via admin.upload_logo().
STATIC_DIR = Path(__file__).parent / "static"

BANNER_WIDTH = 600
BANNER_HEIGHT = 120
BG_COLOR = (20, 33, 61)       # navy — matches the platform's own branding
TEXT_COLOR = (251, 251, 248)  # off-white
ICON_COLOR = (94, 234, 212)   # teal accent


def _draw_shield(draw: ImageDraw.ImageDraw, cx: int, cy: int, size: int):
    """Draws a simple shield shape using plain polygons — no external
    image asset or font glyph needed, so it renders identically everywhere."""
    half = size // 2
    points = [
        (cx, cy - half),
        (cx + half, cy - half * 0.6),
        (cx + half, cy + half * 0.2),
        (cx, cy + half),
        (cx - half, cy + half * 0.2),
        (cx - half, cy - half * 0.6),
    ]
    draw.polygon(points, fill=ICON_COLOR)


def generate_banner(org_name: str) -> bytes:
    img = Image.new("RGB", (BANNER_WIDTH, BANNER_HEIGHT), color=BG_COLOR)
    draw = ImageDraw.Draw(img)

    icon_cx, icon_cy = 50, BANNER_HEIGHT // 2
    _draw_shield(draw, icon_cx, icon_cy, 36)

    text = org_name or "Your Organization"
    text_x = icon_cx + 36
    max_text_width = BANNER_WIDTH - text_x - 20  # leave a right margin

    # load_default(size=...) is a built-in scalable font bundled with
    # Pillow itself — no dependency on fonts installed on the OS, so this
    # works identically on Windows, macOS, and Linux with no setup.
    # Shrink the font until the organization name actually fits the banner,
    # since names vary a lot in length (e.g. "Acme Corp" vs a long Pvt Ltd name).
    font_size = 34
    font = ImageFont.load_default(size=font_size)
    bbox = draw.textbbox((0, 0), text, font=font)
    while (bbox[2] - bbox[0]) > max_text_width and font_size > 14:
        font_size -= 2
        font = ImageFont.load_default(size=font_size)
        bbox = draw.textbbox((0, 0), text, font=font)

    # If it still doesn't fit even at the smallest readable size, truncate.
    while (bbox[2] - bbox[0]) > max_text_width and len(text) > 4:
        text = text[:-4].rstrip() + "..."
        bbox = draw.textbbox((0, 0), text, font=font)

    text_height = bbox[3] - bbox[1]
    text_y = (BANNER_HEIGHT - text_height) // 2 - bbox[1]
    draw.text((text_x, text_y), text, font=font, fill=TEXT_COLOR)

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf.read()


@branding_bp.route("/branding/logo/<int:org_id>.png")
def org_logo(org_id):
    """
    Serves the organization's REAL uploaded logo (admin.upload_logo) when
    one has been set and its file is actually present on disk; falls back
    to the generated placeholder banner otherwise — including when
    logo_path is set but the file has gone missing (e.g. moved between
    servers), so a dangling row never breaks email rendering.
    """
    db = get_db()
    org = db.execute("SELECT name, logo_path FROM organizations WHERE id = ?", (org_id,)).fetchone()
    db.close()

    if org and org["logo_path"]:
        logo_file = STATIC_DIR / org["logo_path"]
        if logo_file.is_file():
            return send_file(logo_file, mimetype="image/png")

    org_name = org["name"] if org else "Your Organization"
    png_bytes = generate_banner(org_name)
    return send_file(io.BytesIO(png_bytes), mimetype="image/png")
