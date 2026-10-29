"""Filtros de plantilla y cálculos de presentación para las vistas HTML (todo en español)."""

from __future__ import annotations

from datetime import UTC
from zoneinfo import ZoneInfo

from app.core import config

SEVERITIES = ("critical", "high", "medium", "low")
_SEVERIDAD = {
    "critical": ("crítico", "críticos"),
    "high": ("alto", "altos"),
    "medium": ("medio", "medios"),
    "low": ("bajo", "bajos"),
}
_ORDEN_SEVERIDAD = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_ESTADOS_ESCANEO = {"pending": "En cola", "running": "En curso", "done": "Finalizado", "failed": "Fallido"}
_MESES = ("ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic")
_CERRADOS = ("resolved", "false_positive")


def _display_tz():
    try:
        return ZoneInfo(config.DISPLAY_TIMEZONE)
    except Exception:  # noqa: BLE001 - zona inválida o sin tzdata: se muestra en UTC
        return UTC


def filtro_fecha(value) -> str:
    if not value:
        return "—"
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    local = value.astimezone(_display_tz())
    return f"{local.day} {_MESES[local.month - 1]} {local.year}, {local:%H:%M}"


def filtro_severidad(value: str, count: int = 1) -> str:
    singular, plural = _SEVERIDAD.get(value, (value, value))
    return singular if count == 1 else plural


def filtro_estado_escaneo(value: str) -> str:
    return _ESTADOS_ESCANEO.get(value, value)


def filtro_por_severidad(findings):
    return sorted(findings, key=lambda f: (_ORDEN_SEVERIDAD.get(f.severity, 9), f.id))


def filtro_conteo_abiertos(findings) -> dict:
    """Hallazgos abiertos (ni resueltos ni falsos positivos) por severidad."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
    for f in findings:
        if f.status in _CERRADOS:
            continue
        if f.severity in counts:
            counts[f.severity] += 1
        counts["total"] += 1
    return counts


def register_filters(env) -> None:
    env.filters.update(
        fecha=filtro_fecha,
        severidad=filtro_severidad,
        estado_escaneo=filtro_estado_escaneo,
        por_severidad=filtro_por_severidad,
        conteo_abiertos=filtro_conteo_abiertos,
    )


# ---------- Cálculos para las vistas ----------


def target_summaries(targets):
    """Devuelve ({target_id: {scan, counts, total}}, fecha del último escaneo)."""
    summaries, last_scan = {}, None
    for t in targets:
        scans = sorted(t.scans, key=lambda s: s.id)
        scan = scans[-1] if scans else None
        counts = filtro_conteo_abiertos(scan.findings if scan else [])
        summaries[t.id] = {"scan": scan, "counts": counts, "total": counts["total"]}
        for s in scans:
            if s.started_at and (last_scan is None or s.started_at > last_scan):
                last_scan = s.started_at
    return summaries, last_scan


def sorted_by_risk(targets, summaries):
    return sorted(
        targets,
        key=lambda t: (-summaries[t.id]["counts"]["critical"], -summaries[t.id]["counts"]["high"], t.name.lower()),
    )


def severity_totals(summaries) -> dict:
    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
    for info in summaries.values():
        for key in totals:
            totals[key] += info["counts"][key]
    return totals


def stacked_bar(totals: dict) -> list[dict]:
    """Segmentos (x, ancho en %) para la barra SVG de severidad; evita estilos inline por la CSP."""
    total = totals["total"]
    if not total:
        return []
    segments, x = [], 0.0
    for sev in SEVERITIES:
        if totals[sev]:
            width = round(totals[sev] * 100 / total, 2)
            segments.append({"sev": sev, "x": round(x, 2), "w": width})
            x += width
    return segments


def open_findings(targets, summaries, severity: str | None = None) -> list[dict]:
    """Hallazgos abiertos del último escaneo de cada objetivo, de más a menos graves."""
    items = []
    for t in targets:
        scan = summaries[t.id]["scan"]
        if not scan:
            continue
        for f in scan.findings:
            if f.status in _CERRADOS or (severity and f.severity != severity):
                continue
            items.append({"finding": f, "target": t, "scan": scan})
    items.sort(key=lambda i: (_ORDEN_SEVERIDAD.get(i["finding"].severity, 9), i["target"].name.lower(), i["finding"].id))
    return items


def recent_scans(targets, limit: int | None = None) -> list[dict]:
    rows = [
        {"scan": s, "target": t, "counts": filtro_conteo_abiertos(s.findings)}
        for t in targets
        for s in t.scans
    ]
    rows.sort(key=lambda r: r["scan"].id, reverse=True)
    return rows[:limit] if limit else rows
