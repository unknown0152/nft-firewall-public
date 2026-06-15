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
        "table_header": "#20283b",
        "table_row_a": "#171d2f",
        "table_row_b": "#1b2236",
        "bar_track": "#30384f",
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
        "table_header": "#eef2f8",
        "table_row_a": "#ffffff",
        "table_row_b": "#f8fafc",
        "bar_track": "#d8deea",
    },
}


@dataclass(frozen=True)
class _Report:
    title: str
    timestamp: str
    status: str
    reason: str
    sections: dict[str, list[str]]


@dataclass(frozen=True)
class _PortRow:
    port: str
    scope: str
    service: str


@dataclass(frozen=True)
class _SystemStats:
    cpu: str
    ram: str
    disk: str
    disk_label: str
    disk_percent: int | None
    ram_ratio: float
    disk_ratio: float
    load_ratio: float


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


def _port_rows(parsed: _Report) -> list[_PortRow]:
    rows: list[_PortRow] = []
    for item in parsed.sections.get("Docker", []):
        match = _PORT_RE.search(item)
        if not match:
            continue
        port, detail = match.groups()
        if "—" in detail:
            scope, service = [part.strip() for part in detail.split("—", 1)]
        else:
            scope, service = "Unknown", detail.strip()
        service = re.sub(r"\s+from\s+(?:LAN|VPN)\b", "", service, flags=re.IGNORECASE)
        rows.append(_PortRow(port=port, scope=scope, service=service))
    return rows


def _system_stats(parsed: _Report) -> _SystemStats:
    items = parsed.sections.get("System", [])
    cpu = _first_value(items, "CPU", "unknown")
    ram = _first_value(items, "RAM", "unknown")
    disk = _first_value(items, "Disk", "unknown")

    load_ratio = 0.0
    cpu_match = re.search(r"([0-9.]+)", cpu)
    if cpu_match:
        load_ratio = min(float(cpu_match.group(1)) / 4.0, 1.0)

    ram_ratio = 0.0
    ram_match = re.search(r"([0-9.]+)GB\s*/\s*([0-9.]+)GB", ram)
    if ram_match:
        used, total = float(ram_match.group(1)), float(ram_match.group(2))
        if total:
            ram_ratio = min(used / total, 1.0)

    disk_ratio = 0.0
    disk_percent = None
    disk_label = disk
    disk_match = re.search(r"(\d+)%", disk)
    if disk_match:
        disk_percent = int(disk_match.group(1))
        disk_ratio = min(disk_percent / 100.0, 1.0)
        mount_match = re.search(r"(.+?)\s+is\s+\d+%\s+full", disk)
        mount = mount_match.group(1).strip() if mount_match else "disk"
        disk_label = "Root used" if mount == "/" else f"{mount} used"

    return _SystemStats(
        cpu=cpu,
        ram=ram,
        disk=disk,
        disk_label=disk_label,
        disk_percent=disk_percent,
        ram_ratio=ram_ratio,
        disk_ratio=disk_ratio,
        load_ratio=load_ratio,
    )


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
    draw.rounded_rectangle((x1 + 18, y1 + 20, x1 + 70, y1 + 72), radius=16, fill=accent)
    draw.text((x1 + 32, y1 + 34), label[:2].upper(), font=label_font, fill="#ffffff")
    draw.text((x1 + 88, y1 + 24), label.upper(), font=label_font, fill=palette["muted"])
    _draw_text_block(
        draw,
        value,
        (x1 + 88, y1 + 58),
        font=value_font,
        fill=palette["text"],
        max_width=x2 - x1 - 112,
    )


def _draw_background(draw, width: int, height: int, palette: dict[str, str]) -> None:
    if palette["background"] != "#0b1020":
        return
    for x in range(-height, width, 92):
        draw.line((x, height, x + height, 0), fill="#10192d", width=1)
    for y in range(640, height, 72):
        draw.line((0, y, width, y), fill="#0f172a", width=1)


def _draw_header_art(draw, box: tuple[int, int, int, int]) -> None:
    x1, y1, x2, y2 = box
    cx = (x1 + x2) // 2 + 180
    cy = y1 + 118
    shield = [
        (cx, cy - 72),
        (cx + 58, cy - 48),
        (cx + 48, cy + 36),
        (cx, cy + 86),
        (cx - 48, cy + 36),
        (cx - 58, cy - 48),
    ]
    draw.polygon(shield, fill="#1e3a5f", outline="#67e8f9")
    inner = [(cx, cy - 42), (cx + 30, cy - 28), (cx + 24, cy + 22), (cx, cy + 52), (cx - 24, cy + 22), (cx - 30, cy - 28)]
    draw.polygon(inner, fill="#172554", outline="#22d3ee")
    for i, h in enumerate([34, 58, 78, 46, 66, 38]):
        bx = cx + 110 + i * 22
        draw.rounded_rectangle((bx, cy + 58 - h, bx + 10, cy + 58), radius=3, fill="#164e63")
    for i, h in enumerate([28, 48, 35, 60, 42]):
        bx = cx - 210 + i * 28
        draw.rounded_rectangle((bx, cy + 64 - h, bx + 13, cy + 64), radius=3, fill="#0f3d56")


def _draw_progress_bar(
    draw,
    box: tuple[int, int, int, int],
    *,
    ratio: float,
    fill: str,
    track: str,
) -> None:
    x1, y1, x2, y2 = box
    ratio = max(0.0, min(ratio, 1.0))
    draw.rounded_rectangle(box, radius=(y2 - y1) // 2, fill=track)
    draw.rounded_rectangle((x1, y1, x1 + int((x2 - x1) * ratio), y2), radius=(y2 - y1) // 2, fill=fill)


def _draw_donut(
    draw,
    box: tuple[int, int, int, int],
    *,
    ratio: float,
    fill: str,
    track: str,
    text: str,
    font,
    palette: dict[str, str],
) -> None:
    ratio = max(0.0, min(ratio, 1.0))
    draw.arc(box, start=0, end=360, fill=track, width=24)
    draw.arc(box, start=-90, end=-90 + int(360 * ratio), fill=fill, width=24)
    tx1, ty1, tx2, ty2 = draw.textbbox((0, 0), text, font=font)
    cx = (box[0] + box[2]) // 2
    cy = (box[1] + box[3]) // 2
    draw.text((cx - (tx2 - tx1) // 2, cy - (ty2 - ty1) // 2 - 2), text, font=font, fill=palette["text"])


def _draw_docker_panel(
    draw,
    box: tuple[int, int, int, int],
    *,
    parsed: _Report,
    heading_font,
    body_font,
    small_font,
    palette: dict[str, str],
) -> None:
    x1, y1, x2, y2 = box
    rows = _port_rows(parsed)
    runtime = _first_value(parsed.sections.get("Docker", []), "Runtime", "unknown")
    _draw_shadow_card(draw, box, palette=palette, radius=24)
    draw.rounded_rectangle((x1 + 24, y1 + 26, x1 + 38, y1 + 62), radius=6, fill="#32ade6")
    draw.text((x1 + 56, y1 + 20), "Docker Overview", font=heading_font, fill=palette["text"])

    table_x = x1 + 28
    table_y = y1 + 82
    table_w = x2 - x1 - 56
    header_h = 52
    draw.rounded_rectangle((table_x, table_y, table_x + table_w, table_y + header_h), radius=12, fill=palette["table_header"])
    draw.text((table_x + 18, table_y + 14), "Port", font=small_font, fill=palette["text"])
    draw.text((table_x + 205, table_y + 14), "Service / Application", font=small_font, fill=palette["text"])
    draw.text((table_x + table_w - 150, table_y + 14), "Scope", font=small_font, fill=palette["text"])

    row_y = table_y + header_h
    row_h = 47
    for index, row in enumerate(rows[:9]):
        fill = palette["table_row_a"] if index % 2 == 0 else palette["table_row_b"]
        draw.rounded_rectangle((table_x, row_y, table_x + table_w, row_y + row_h), radius=8, fill=fill)
        chip_color = "#133d5e" if row.scope == "VPN" else "#533b1e"
        chip_text = "#7cc7ff" if row.scope == "VPN" else "#ffbd66"
        draw.rounded_rectangle((table_x + 18, row_y + 9, table_x + 146, row_y + 38), radius=9, fill=chip_color)
        draw.text((table_x + 32, row_y + 12), row.port, font=small_font, fill=chip_text)
        draw.text((table_x + 205, row_y + 10), row.service[:34], font=body_font, fill=palette["text"])
        scope_color = "#72e6a3" if row.scope == "LAN" else "#8ab4ff"
        draw.ellipse((table_x + table_w - 146, row_y + 13, table_x + table_w - 118, row_y + 41), fill=scope_color)
        draw.text((table_x + table_w - 108, row_y + 10), row.scope, font=body_font, fill=scope_color)
        row_y += row_h

    runtime_y = y2 - 82
    draw.line((table_x, runtime_y - 22, table_x + table_w, runtime_y - 22), fill=palette["card_outline"], width=2)
    draw.text((table_x + 16, runtime_y), f"Runtime: {runtime}", font=heading_font, fill=palette["text"])


def _draw_daemons_system_panel(
    draw,
    box: tuple[int, int, int, int],
    *,
    parsed: _Report,
    heading_font,
    body_font,
    small_font,
    value_font,
    palette: dict[str, str],
) -> None:
    x1, y1, x2, y2 = box
    stats = _system_stats(parsed)
    daemons = parsed.sections.get("Daemons", [])
    _draw_shadow_card(draw, box, palette=palette, radius=24)
    draw.rounded_rectangle((x1 + 24, y1 + 26, x1 + 38, y1 + 62), radius=6, fill="#5856d6")
    draw.text((x1 + 56, y1 + 20), "Daemons & System", font=heading_font, fill=palette["text"])

    daemon_x = x1 + 42
    y = y1 + 86
    for item in daemons:
        label = item.removeprefix("•").strip()
        draw.ellipse((daemon_x, y + 9, daemon_x + 14, y + 23), fill="#72e6a3")
        draw.text((daemon_x + 28, y), label, font=body_font, fill=palette["text"])
        y += 42

    bar_x = x1 + 360
    label_y = y1 + 88
    track = palette["bar_track"]
    for label, value, ratio, accent in [
        ("CPU load", stats.cpu, stats.load_ratio, "#0a84ff"),
        ("RAM", stats.ram, stats.ram_ratio, "#34c759"),
    ]:
        draw.text((bar_x, label_y), label, font=small_font, fill=palette["muted"])
        draw.text((bar_x + 300, label_y - 2), value, font=body_font, fill=palette["text"])
        _draw_progress_bar(draw, (bar_x, label_y + 36, bar_x + 540, label_y + 62), ratio=ratio, fill=accent, track=track)
        label_y += 92

    disk_box = (x2 - 184, y1 + 74, x2 - 44, y1 + 214)
    disk_text = f"{stats.disk_percent}%" if stats.disk_percent is not None else "—"
    _draw_donut(
        draw,
        disk_box,
        ratio=stats.disk_ratio,
        fill="#34c759",
        track=track,
        text=disk_text,
        font=value_font,
        palette=palette,
    )
    label = "Disk"
    detail = stats.disk_label
    label_bbox = draw.textbbox((0, 0), label, font=small_font)
    detail_bbox = draw.textbbox((0, 0), detail, font=body_font)
    disk_center = (disk_box[0] + disk_box[2]) // 2
    draw.text((disk_center - (label_bbox[2] - label_bbox[0]) // 2, y1 + 226), label, font=small_font, fill=palette["muted"])
    draw.text((disk_center - (detail_bbox[2] - detail_bbox[0]) // 2, y1 + 254), detail, font=body_font, fill=palette["text"])


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
    left_w = 430
    right_w = width - margin * 2 - gap - left_w

    title_font = ImageFont.truetype(str(_FONT_BOLD), 52)
    subtitle_font = ImageFont.truetype(str(_FONT_REGULAR), 25)
    status_font = ImageFont.truetype(str(_FONT_BOLD), 31)
    metric_label_font = ImageFont.truetype(str(_FONT_BOLD), 17)
    metric_value_font = ImageFont.truetype(str(_FONT_REGULAR), 24)
    section_font = ImageFont.truetype(str(_FONT_BOLD), 30)
    body_font = ImageFont.truetype(str(_FONT_REGULAR), 24)
    small_font = ImageFont.truetype(str(_FONT_BOLD), 19)

    height = 1780

    image = Image.new("RGB", (width, height), palette["background"])
    draw = ImageDraw.Draw(image)
    _draw_background(draw, width, height, palette)

    # Header.
    header = (margin, 44, width - margin, 296)
    _draw_shadow_card(draw, header, palette=palette, radius=34, fill=palette["header"])
    draw.rounded_rectangle((margin + 28, 72, margin + 42, 268), radius=7, fill="#0a84ff")
    draw.text((margin + 70, 76), "NFT Firewall", font=subtitle_font, fill="#a7c7ff")
    draw.text((margin + 70, 112), "Daily Security Brief", font=title_font, fill="#ffffff")
    draw.text((margin + 74, 184), parsed.timestamp or "Current status report", font=subtitle_font, fill="#d0d5dd")
    _draw_header_art(draw, header)

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
    metric_h = 112
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
    detail_y = metric_y + metric_h * 2 + metric_gap + 42
    right_x = margin + left_w + gap
    left_sections = [
        ("Network", parsed.sections.get("Network", []), 250),
        ("Security", parsed.sections.get("Security", []), 300),
    ]
    y = detail_y
    for name, items, panel_h in left_sections:
        if items:
            _draw_section(
                draw=draw,
                box=(margin, y, margin + left_w, y + panel_h),
                section=name,
                items=items,
                heading_font=section_font,
                body_font=body_font,
                small_font=small_font,
                palette=palette,
            )
            y += panel_h + gap

    _draw_docker_panel(
        draw,
        (right_x, detail_y, width - margin, detail_y + 650),
        parsed=parsed,
        heading_font=section_font,
        body_font=body_font,
        small_font=small_font,
        palette=palette,
    )

    bottom_y = detail_y + 650 + gap
    _draw_daemons_system_panel(
        draw,
        (margin, bottom_y, width - margin, bottom_y + 288),
        parsed=parsed,
        heading_font=section_font,
        body_font=body_font,
        small_font=small_font,
        value_font=status_font,
        palette=palette,
    )

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
