"""PNG renderer for the Keybase daily firewall report."""

from __future__ import annotations

import re
import tempfile
from dataclasses import dataclass
from pathlib import Path


_FONT_REGULAR = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
_FONT_BOLD = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")
_MARKUP_RE = re.compile(r"[*_`]")
_PORT_RE = re.compile(r"`?([^`\s]+/(?:tcp|udp))`?\s+(.+)")

_PALETTES = {
    "dark": {
        "background": "#0b1020",
        "header": "#111827",
        "header_outline": "#273449",
        "shadow": "#050814",
        "card": "#161b2d",
        "card_outline": "#2a3448",
        "text": "#f8fafc",
        "muted": "#aeb7c8",
        "footer": "#7d89a3",
        "chip": "#102a46",
        "chip_text": "#7cc7ff",
        "status_ok_fill": "#133d2a",
        "status_ok_text": "#72e6a3",
        "status_bad_fill": "#4a141b",
        "status_bad_text": "#ff8a98",
    },
    "light": {
        "background": "#eef2f8",
        "header": "#101828",
        "header_outline": "#d9dde6",
        "shadow": "#dde1ea",
        "card": "#ffffff",
        "card_outline": "#d9dde6",
        "text": "#1d1d1f",
        "muted": "#6e6e73",
        "footer": "#667085",
        "chip": "#eef5ff",
        "chip_text": "#0066cc",
        "status_ok_fill": "#163f2a",
        "status_ok_text": "#7ee2a8",
        "status_bad_fill": "#4a141b",
        "status_bad_text": "#ff8a98",
    },
}


@dataclass(frozen=True)
class _Report:
    title: str
    timestamp: str
    status: str
    reason: str
    sections: dict[str, list[str]]


def _plain(line: str) -> str:
    """Remove lightweight chat markup while keeping readable text."""
    return _MARKUP_RE.sub("", line).strip()


def _without_emoji(text: str) -> str:
    """Keep the image report readable with fonts that lack color emoji."""
    return "".join(ch for ch in text if ord(ch) < 0x2600 or ch in {"•", "—"})


def _clean(line: str) -> str:
    return _without_emoji(_plain(line)).strip()


def _parse_report(report: str) -> _Report:
    title = "Good Morning — Firewall Brief"
    timestamp = ""
    status = "UNKNOWN"
    reason = ""
    current = ""
    sections: dict[str, list[str]] = {}

    for raw_line in report.splitlines():
        line = _clean(raw_line)
        if not line:
            continue
        if line.startswith("Good Morning"):
            title = line
        elif re.match(r"^[A-Z][a-z]{2},", line):
            timestamp = line
        elif line in {"HEALTHY", "DEGRADED"}:
            status = line
        elif line in {"Network", "Security", "Docker", "Daemons", "System", "Weekly Auto-Blocks"}:
            current = line
            sections.setdefault(current, [])
        elif line.startswith("•") or raw_line.startswith("  "):
            if current:
                sections.setdefault(current, []).append(line)
        elif status == "DEGRADED" and not reason:
            reason = line

    return _Report(
        title=title,
        timestamp=timestamp,
        status=status,
        reason=reason,
        sections=sections,
    )


def _first_value(items: list[str], prefix: str, fallback: str = "Unknown") -> str:
    for item in items:
        cleaned = item.removeprefix("•").strip()
        if cleaned.startswith(prefix):
            return cleaned.split(":", 1)[1].strip()
    return fallback


def _metric_rows(parsed: _Report) -> list[tuple[str, str, str]]:
    network = parsed.sections.get("Network", [])
    security = parsed.sections.get("Security", [])
    docker = parsed.sections.get("Docker", [])

    return [
        ("VPN", _first_value(network, "VPN"), "#007aff"),
        ("Handshake", _first_value(network, "Handshake"), "#34c759"),
        ("Killswitch", _first_value(security, "Killswitch"), "#ff9f0a"),
        ("NFT rules", _first_value(security, "NFT rules"), "#5856d6"),
        ("Docker", _first_value(docker, "Runtime"), "#32ade6"),
        ("Drops", _first_value(security, "Firewall drops", "0 packets denied"), "#ff453a"),
    ]


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


def _line_height(draw, font, padding: int = 10) -> int:
    bbox = draw.textbbox((0, 0), "Ag", font=font)
    return bbox[3] - bbox[1] + padding


def _draw_shadow_card(
    draw,
    box: tuple[int, int, int, int],
    *,
    palette: dict[str, str],
    radius: int = 26,
    fill: str | None = None,
) -> None:
    x1, y1, x2, y2 = box
    draw.rounded_rectangle((x1 + 4, y1 + 5, x2 + 4, y2 + 5), radius=radius, fill=palette["shadow"])
    draw.rounded_rectangle(
        box,
        radius=radius,
        fill=fill or palette["card"],
        outline=palette["card_outline"],
        width=1,
    )


def _draw_text_block(draw, text: str, xy: tuple[int, int], *, font, fill: str, max_width: int) -> int:
    x, y = xy
    for wrapped in _wrap_text(draw, text, font, max_width):
        draw.text((x, y), wrapped, font=font, fill=fill)
        y += _line_height(draw, font, 8)
    return y


def _draw_metric_card(
    draw,
    box: tuple[int, int, int, int],
    *,
    label: str,
    value: str,
    accent: str,
    label_font,
    value_font,
    palette: dict[str, str],
) -> None:
    x1, y1, x2, y2 = box
    _draw_shadow_card(draw, box, palette=palette, radius=22)
    draw.rounded_rectangle((x1 + 18, y1 + 18, x1 + 28, y2 - 18), radius=5, fill=accent)
    draw.text((x1 + 44, y1 + 22), label.upper(), font=label_font, fill=palette["muted"])
    _draw_text_block(
        draw,
        value,
        (x1 + 44, y1 + 58),
        font=value_font,
        fill=palette["text"],
        max_width=x2 - x1 - 70,
    )


def _section_title(section: str) -> tuple[str, str]:
    colors = {
        "Network": "#007aff",
        "Security": "#34c759",
        "Docker": "#32ade6",
        "Daemons": "#5856d6",
        "System": "#ff9f0a",
        "Weekly Auto-Blocks": "#ff453a",
    }
    return section, colors.get(section, "#007aff")


def _draw_section(
    draw,
    box: tuple[int, int, int, int],
    *,
    section: str,
    items: list[str],
    heading_font,
    body_font,
    small_font,
    palette: dict[str, str],
) -> None:
    x1, y1, x2, y2 = box
    title, accent = _section_title(section)
    _draw_shadow_card(draw, box, palette=palette, radius=22)
    draw.rounded_rectangle((x1 + 22, y1 + 24, x1 + 34, y1 + 58), radius=5, fill=accent)
    draw.text((x1 + 48, y1 + 20), title, font=heading_font, fill=palette["text"])

    y = y1 + 72
    max_width = x2 - x1 - 56
    for item in items:
        text = item.removeprefix("•").strip()
        port_match = _PORT_RE.search(text)
        if port_match:
            port, detail = port_match.groups()
            draw.rounded_rectangle((x1 + 26, y - 2, x1 + 154, y + 30), radius=10, fill=palette["chip"])
            draw.text((x1 + 40, y + 2), port, font=small_font, fill=palette["chip_text"])
            y = _draw_text_block(
                draw,
                detail,
                (x1 + 170, y),
                font=body_font,
                fill=palette["text"],
                max_width=max_width - 145,
            )
        else:
            draw.ellipse((x1 + 30, y + 8, x1 + 40, y + 18), fill=accent)
            y = _draw_text_block(
                draw,
                text,
                (x1 + 54, y),
                font=body_font,
                fill=palette["text"],
                max_width=max_width - 28,
            )
        y += 7


def render_report_png(report: str, *, output_path: str | Path | None = None, theme: str = "dark") -> Path:
    """Render a status report string to a PNG file and return its path.

    Pillow is intentionally imported lazily so normal text-only operation does
    not depend on image libraries.
    """
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError as exc:  # pragma: no cover - depends on host package set
        raise RuntimeError("Pillow is required for image reports; install python3-pil") from exc

    if theme not in _PALETTES:
        raise ValueError(f"Unsupported image report theme: {theme}")
    palette = _PALETTES[theme]
    parsed = _parse_report(report)

    width = 1400
    margin = 56
    gap = 24
    card_w = (width - margin * 2 - gap) // 2

    title_font = ImageFont.truetype(str(_FONT_BOLD), 52)
    subtitle_font = ImageFont.truetype(str(_FONT_REGULAR), 25)
    status_font = ImageFont.truetype(str(_FONT_BOLD), 31)
    metric_label_font = ImageFont.truetype(str(_FONT_BOLD), 17)
    metric_value_font = ImageFont.truetype(str(_FONT_REGULAR), 24)
    section_font = ImageFont.truetype(str(_FONT_BOLD), 30)
    body_font = ImageFont.truetype(str(_FONT_REGULAR), 24)
    small_font = ImageFont.truetype(str(_FONT_BOLD), 19)

    section_order = ["Network", "Security", "Docker", "Daemons", "System", "Weekly Auto-Blocks"]
    present_sections = [(name, parsed.sections[name]) for name in section_order if parsed.sections.get(name)]
    section_heights: list[int] = []

    scratch = Image.new("RGB", (width, 10), palette["background"])
    draw = ImageDraw.Draw(scratch)
    for _name, items in present_sections:
        lines = 0
        for item in items:
            text = item.removeprefix("•").strip()
            port_match = _PORT_RE.search(text)
            if port_match:
                text = port_match.group(2)
                max_width = card_w - 200
            else:
                max_width = card_w - 84
            lines += len(_wrap_text(draw, text, body_font, max_width))
        section_heights.append(max(174, 95 + lines * _line_height(draw, body_font, 15)))

    rows = [section_heights[i:i + 2] for i in range(0, len(section_heights), 2)]
    height = 360 + 240 + sum(max(row) for row in rows) + max(0, len(rows) - 1) * gap + 70

    image = Image.new("RGB", (width, height), palette["background"])
    draw = ImageDraw.Draw(image)

    # Header.
    header = (margin, 44, width - margin, 296)
    _draw_shadow_card(draw, header, palette=palette, radius=34, fill=palette["header"])
    draw.rounded_rectangle((margin + 28, 72, margin + 42, 268), radius=7, fill="#0a84ff")
    draw.text((margin + 70, 76), "NFT Firewall", font=subtitle_font, fill="#a7c7ff")
    draw.text((margin + 70, 112), "Daily Security Brief", font=title_font, fill="#ffffff")
    draw.text((margin + 74, 184), parsed.timestamp or "Current status report", font=subtitle_font, fill="#d0d5dd")

    status_ok = parsed.status == "HEALTHY"
    pill_fill = palette["status_ok_fill"] if status_ok else palette["status_bad_fill"]
    pill_text = palette["status_ok_text"] if status_ok else palette["status_bad_text"]
    pill = (width - margin - 285, 86, width - margin - 44, 146)
    draw.rounded_rectangle(pill, radius=24, fill=pill_fill)
    draw.text((pill[0] + 34, pill[1] + 13), parsed.status, font=status_font, fill=pill_text)
    if parsed.reason:
        _draw_text_block(
            draw,
            parsed.reason,
            (width - margin - 430, 170),
            font=subtitle_font,
            fill="#f2f4f7",
            max_width=380,
        )

    # Metric cards.
    metric_y = 328
    metric_h = 96
    metric_gap = 18
    metric_w = (width - margin * 2 - metric_gap * 2) // 3
    for index, (label, value, accent) in enumerate(_metric_rows(parsed)):
        row = index // 3
        col = index % 3
        x1 = margin + col * (metric_w + metric_gap)
        y1 = metric_y + row * (metric_h + metric_gap)
        _draw_metric_card(
            draw,
            (x1, y1, x1 + metric_w, y1 + metric_h),
            label=label,
            value=value,
            accent=accent,
            label_font=metric_label_font,
            value_font=metric_value_font,
            palette=palette,
        )

    # Detail sections.
    y = metric_y + metric_h * 2 + metric_gap + 42
    for row_index in range(0, len(present_sections), 2):
        row_sections = present_sections[row_index:row_index + 2]
        row_heights = section_heights[row_index:row_index + 2]
        row_h = max(row_heights)
        for col, (name, items) in enumerate(row_sections):
            x1 = margin + col * (card_w + gap)
            _draw_section(
                draw,
                (x1, y, x1 + card_w, y + row_h),
                section=name,
                items=items,
                heading_font=section_font,
                body_font=body_font,
                small_font=small_font,
                palette=palette,
            )
        y += row_h + gap

    draw.text(
        (margin, height - 44),
        "Generated by nft-firewall",
        font=subtitle_font,
        fill=palette["footer"],
    )

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
