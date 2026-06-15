"""PNG renderer for the Keybase daily firewall report."""

from __future__ import annotations

import re
import tempfile
from pathlib import Path


_FONT_REGULAR = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
_FONT_BOLD = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")
_MARKUP_RE = re.compile(r"[*_`]")


def _plain(line: str) -> str:
    """Remove lightweight chat markup while keeping readable text."""
    return _MARKUP_RE.sub("", line).strip()


def _without_emoji(text: str) -> str:
    """Keep the image report readable with fonts that lack color emoji."""
    return "".join(ch for ch in text if ord(ch) < 0x2600 or ch in {"•", "—"})


def _wrap_text(draw, text: str, font, max_width: int) -> list[str]:
    words = text.split()
    if not words:
        return [""]

    lines: list[str] = []
    current = words[0]
    for word in words[1:]:
        candidate = f"{current} {word}"
        if draw.textbbox((0, 0), candidate, font=font)[2] <= max_width:
            current = candidate
        else:
            lines.append(current)
            current = word
    lines.append(current)
    return lines


def render_report_png(report: str, *, output_path: str | Path | None = None) -> Path:
    """Render a status report string to a PNG file and return its path.

    Pillow is intentionally imported lazily so normal text-only operation does
    not depend on image libraries.
    """
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError as exc:  # pragma: no cover - depends on host package set
        raise RuntimeError("Pillow is required for image reports; install python3-pil") from exc

    width = 1200
    margin = 56
    card_x = margin
    card_w = width - margin * 2
    y = 48
    max_text_w = card_w - 64

    title_font = ImageFont.truetype(str(_FONT_BOLD), 42)
    section_font = ImageFont.truetype(str(_FONT_BOLD), 27)
    body_font = ImageFont.truetype(str(_FONT_REGULAR), 25)
    small_font = ImageFont.truetype(str(_FONT_REGULAR), 20)

    cleaned = [_without_emoji(_plain(line)) for line in report.splitlines()]
    rows: list[tuple[str, str]] = []
    for line in cleaned:
        if not line:
            rows.append(("space", ""))
        elif line.startswith("Good Morning"):
            rows.append(("title", line))
        elif line.startswith(("Network", "Security", "Docker", "Daemons", "System", "Weekly")):
            rows.append(("section", line))
        elif line.startswith("HEALTHY") or line.startswith("DEGRADED"):
            rows.append(("status", line))
        elif line.startswith("•"):
            rows.append(("body", line))
        else:
            rows.append(("small", line))

    # First pass: measure height.
    scratch = Image.new("RGB", (width, 10), "#f5f5f7")
    draw = ImageDraw.Draw(scratch)
    height = y + 40
    for kind, text in rows:
        if kind == "space":
            height += 16
            continue
        font = {
            "title": title_font,
            "section": section_font,
            "status": section_font,
            "body": body_font,
            "small": small_font,
        }[kind]
        wrapped = _wrap_text(draw, text, font, max_text_w)
        line_h = draw.textbbox((0, 0), "Ag", font=font)[3] + 10
        height += len(wrapped) * line_h + (12 if kind in {"section", "status"} else 4)

    height += 70
    image = Image.new("RGB", (width, height), "#f5f5f7")
    draw = ImageDraw.Draw(image)

    # Card background.
    draw.rounded_rectangle(
        (card_x, 32, card_x + card_w, height - 32),
        radius=28,
        fill="#ffffff",
        outline="#d8d8df",
        width=2,
    )

    accent = "#007aff"
    text_color = "#1d1d1f"
    muted = "#6e6e73"
    green = "#248a3d"
    red = "#d70015"

    x = card_x + 32
    y = 64
    for kind, text in rows:
        if kind == "space":
            y += 12
            continue

        font = {
            "title": title_font,
            "section": section_font,
            "status": section_font,
            "body": body_font,
            "small": small_font,
        }[kind]
        color = {
            "title": text_color,
            "section": accent,
            "status": green if "HEALTHY" in text else red,
            "body": text_color,
            "small": muted,
        }[kind]

        if kind == "section":
            draw.rounded_rectangle((x, y + 4, x + 8, y + 34), radius=4, fill=accent)
            text_x = x + 22
        else:
            text_x = x

        for wrapped in _wrap_text(draw, text, font, max_text_w - (text_x - x)):
            draw.text((text_x, y), wrapped, font=font, fill=color)
            y += draw.textbbox((0, 0), "Ag", font=font)[3] + 10
        if kind in {"title", "status", "section"}:
            y += 10

    if output_path is None:
        tmp = tempfile.NamedTemporaryFile(
            prefix="nft-firewall-report-",
            suffix=".png",
            delete=False,
        )
        output = Path(tmp.name)
        tmp.close()
    else:
        output = Path(output_path)
    image.save(output, "PNG", optimize=True)
    output.chmod(0o644)
    return output
