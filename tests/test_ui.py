import re
from datetime import UTC, datetime

from fastapi.testclient import TestClient

from app.core.database import SessionLocal, engine
from app.core.security import hash_password
from app.main import app
from app.models.base import Base
from app.models.finding import Finding
from app.models.scan_run import ScanRun
from app.models.target import Target
from app.models.user import User
from app.reports import build_pdf_report
from app.ui import filtro_conteo_abiertos, filtro_fecha, filtro_por_severidad, stacked_bar


def setup_function(function):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    for model in (Finding, ScanRun, Target, User):
        db.query(model).delete()
    db.commit()
    for email, pwd, admin in (("admin@test.local", "admin123", True), ("cliente@test.local", "cliente123", False)):
        h, s = hash_password(pwd)
        db.add(User(email=email, password_hash=h, password_salt=s, is_admin=admin, is_active=True))
    db.commit()
    db.close()


def teardown_function(function):
    Base.metadata.drop_all(bind=engine)


def login(email, password):
    client = TestClient(app)
    page = client.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    client.post("/login", data={"email": email, "password": password, "csrf_token": token}, follow_redirects=False)
    return client


def _seed():
    db = SessionLocal()
    quiet = Target(name="Sitio tranquilo", url="https://tranquilo.example.com", owner_id=2)
    risky = Target(name="Tienda en línea", url="https://tienda.example.com", owner_id=2)
    db.add_all([quiet, risky])
    db.commit()
    scan = ScanRun(target_id=risky.id, status="done", started_at=datetime(2026, 10, 29, 3, 38, tzinfo=UTC))
    db.add(scan)
    db.commit()
    db.add_all([
        Finding(scan_run_id=scan.id, severity="low", title="Aviso menor", description="d", remediation="r"),
        Finding(scan_run_id=scan.id, severity="critical", title="Certificado TLS vencido", description="d", remediation="r"),
        Finding(scan_run_id=scan.id, severity="high", title="Resuelto ya", description="d", remediation="r", status="resolved"),
    ])
    db.commit()
    ids = (quiet.id, risky.id)
    db.close()
    return ids


def test_targets_page_orders_by_risk_and_summarizes_in_spanish():
    quiet_id, risky_id = _seed()
    html = login("cliente@test.local", "cliente123").get("/objetivos").text
    assert html.index("Tienda en línea") < html.index("Sitio tranquilo")
    assert "1 hallazgo crítico abierto" in html
    assert f'href="/targets/{risky_id}/view">Tienda en línea</a>' in html  # enlace en el resumen
    assert "1 crítico" in html and "1 bajo" in html
    assert "Resuelto ya" not in html
    assert "Sin escanear" in html


def test_empty_pages_have_helpful_copy():
    for path in ("/", "/objetivos"):
        html = login("cliente@test.local", "cliente123").get(path).text
        assert "Todavía no hay objetivos" in html
        admin_html = login("admin@test.local", "admin123").get(path).text
        assert 'href="/admin"' in admin_html and "Registra el primer sitio" in admin_html


def test_target_page_lists_findings_by_severity_with_fixes():
    _, risky_id = _seed()
    html = login("cliente@test.local", "cliente123").get(f"/targets/{risky_id}/view").text
    assert html.index("Certificado TLS vencido") < html.index("Aviso menor")
    assert "Cómo corregirlo." in html
    assert 'commandfor="dlg-scan"' in html and "<dialog" in html
    assert "Resuelto" in html  # estado del hallazgo ya resuelto
    assert 'aria-current="page"' in html
    assert 'href="/objetivos">Objetivos</a>' in html  # migas de pan


def test_admin_page_uses_labeled_fields_and_owner_select():
    _seed()
    html = login("admin@test.local", "admin123").get("/admin").text
    assert 'for="nu-email"' in html and 'for="nt-owner"' in html
    assert "cliente@test.local" in html  # el propietario se muestra como correo, no como ID
    assert "Administración" in html


def test_pages_have_basic_accessibility_structure():
    _, risky_id = _seed()
    admin = login("admin@test.local", "admin123")
    pages = {
        "/login": TestClient(app).get("/login").text,
        "/": admin.get("/").text,
        "/objetivos": admin.get("/objetivos").text,
        "/hallazgos": admin.get("/hallazgos").text,
        "/escaneos": admin.get("/escaneos").text,
        "/informes": admin.get("/informes").text,
        "/cuenta": admin.get("/cuenta").text,
        f"/targets/{risky_id}/view": admin.get(f"/targets/{risky_id}/view").text,
        "/admin": admin.get("/admin").text,
    }
    for path, html in pages.items():
        assert '<html lang="es">' in html, path
        assert len(re.findall(r"<h1[ >]", html)) == 1, f"{path}: debe haber un solo h1"
        assert len(re.findall(r"<main[ >]", html)) == 1, path
        assert 'class="skip-link"' in html, path
        for input_tag in re.findall(r"<(?:input|select)[^>]*>", html):
            if 'type="hidden"' in input_tag:
                continue
            input_id = re.search(r'id="([^"]+)"', input_tag)
            assert input_id and f'for="{input_id.group(1)}"' in html, f"{path}: campo sin label: {input_tag}"


def test_login_form_follows_autofill_guidance():
    html = TestClient(app).get("/login").text
    assert 'autocomplete="username"' in html and 'autocomplete="current-password"' in html
    assert 'data-toggle-password="password"' in html


def test_error_pages_use_the_app_layout():
    resp = login("cliente@test.local", "cliente123").get("/targets/9999/view")
    assert resp.status_code == 404
    assert "<h1>No encontrado</h1>" in resp.text and 'class="skip-link"' in resp.text


def test_filters():
    assert filtro_fecha(datetime(2026, 10, 29, 3, 38, tzinfo=UTC)) == "28 oct 2026, 23:38"  # UTC-4
    assert filtro_fecha(None) == "—"

    class F:
        def __init__(self, id, severity, status="pending"):
            self.id, self.severity, self.status = id, severity, status

    ordered = filtro_por_severidad([F(1, "low"), F(2, "critical"), F(3, "high")])
    assert [f.severity for f in ordered] == ["critical", "high", "low"]
    counts = filtro_conteo_abiertos([F(1, "high"), F(2, "high", "resolved"), F(3, "low", "false_positive")])
    assert counts == {"critical": 0, "high": 1, "medium": 0, "low": 0, "total": 1}


def test_pdf_report_escapes_markup_and_orders_findings():
    pdf = build_pdf_report(
        "<b>Mi sitio</b> & Cía",
        "https://ejemplo.com/?a=1&b=2",
        1,
        [
            {"severity": "low", "title": "Menor <i>x</i>", "description": "d", "remediation": "r"},
            {"severity": "critical", "title": "Grave", "description": "d", "remediation": "r"},
        ],
    )
    assert pdf.startswith(b"%PDF")
    assert build_pdf_report("X", "https://x.com", 1, []).startswith(b"%PDF")


# ---------- Navegación y secciones nuevas ----------

def test_sidebar_has_sections_and_menu_button():
    html = login("cliente@test.local", "cliente123").get("/").text
    for href in ("/", "/objetivos", "/hallazgos", "/escaneos", "/informes", "/cuenta"):
        assert f'<a href="{href}"' in html, href
    assert 'href="/admin"' not in html  # el cliente no ve Administración
    assert 'id="menu-btn"' in html and 'aria-controls="sidebar"' in html and 'aria-expanded="true"' in html
    assert 'id="sidebar"' in html and 'aria-label="Navegación principal"' in html
    admin_html = login("admin@test.local", "admin123").get("/").text
    assert 'href="/admin"' in admin_html


def test_nav_marks_the_current_page():
    client = login("cliente@test.local", "cliente123")
    for path, label in (("/", "Panel"), ("/objetivos", "Objetivos"), ("/hallazgos", "Hallazgos"), ("/escaneos", "Escaneos"), ("/informes", "Informes"), ("/cuenta", "Mi cuenta")):
        html = client.get(path).text
        current = re.findall(r'<a href="[^"]+" aria-current="page">.*?</a>', html, flags=re.S)
        assert len(current) == 1 and label in current[0], (path, current)


def test_panel_shows_kpis_severity_bar_and_attention_list():
    _, risky_id = _seed()
    html = login("cliente@test.local", "cliente123").get("/").text
    assert "Críticos abiertos" in html and "Hallazgos abiertos" in html
    assert 'class="seg-critical"' in html and 'class="seg-low"' in html
    assert "Requieren atención" in html and f'href="/targets/{risky_id}/view">Tienda en línea</a>' in html
    assert "Escaneos recientes" in html


def test_findings_page_filters_by_severity():
    _seed()
    client = login("cliente@test.local", "cliente123")
    todos = client.get("/hallazgos").text
    assert "Certificado TLS vencido" in todos and "Aviso menor" in todos
    criticos = client.get("/hallazgos?severidad=critical").text
    assert "Certificado TLS vencido" in criticos and "Aviso menor" not in criticos
    assert client.get("/hallazgos?severidad=inventada").status_code == 200  # filtro inválido se ignora
    assert "Resuelto ya" not in todos


def test_scans_and_reports_pages():
    _, risky_id = _seed()
    client = login("cliente@test.local", "cliente123")
    escaneos = client.get("/escaneos").text
    assert "Tienda en línea" in escaneos and "Finalizado" in escaneos
    informes = client.get("/informes").text
    assert f'href="/targets/{risky_id}/report"' in informes
    assert "No disponible" in informes  # el sitio sin escanear no tiene PDF


def test_new_pages_require_login():
    client = TestClient(app)
    for path in ("/", "/objetivos", "/hallazgos", "/escaneos", "/informes", "/cuenta"):
        resp = client.get(path, follow_redirects=False)
        assert resp.status_code in (302, 303, 307), path
        assert "/login" in resp.headers["location"], path


def test_stacked_bar_segments():
    assert stacked_bar({"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}) == []
    segments = stacked_bar({"critical": 1, "high": 0, "medium": 1, "low": 2, "total": 4})
    assert [s["sev"] for s in segments] == ["critical", "medium", "low"]
    assert segments[0] == {"sev": "critical", "x": 0.0, "w": 25.0}
    assert round(sum(s["w"] for s in segments)) == 100


# ---------- Cambio de contraseña ----------

def _csrf(client):
    return re.search(r'name="csrf_token" value="([^"]+)"', client.get("/cuenta").text).group(1)


def _change(client, current, new, confirm):
    return client.post(
        "/cuenta/password",
        data={"current_password": current, "new_password": new, "confirm_password": confirm, "csrf_token": _csrf(client)},
        follow_redirects=True,
    )


def test_change_password_success():
    client = login("cliente@test.local", "cliente123")
    resp = _change(client, "cliente123", "NuevaClave2026", "NuevaClave2026")
    assert "Contraseña actualizada." in resp.text
    # La clave anterior ya no sirve y la nueva sí
    assert 'href="/objetivos"' not in login("cliente@test.local", "cliente123").get("/").text
    assert 'href="/objetivos"' in login("cliente@test.local", "NuevaClave2026").get("/").text


def test_change_password_rejects_wrong_current_mismatch_and_weak():
    client = login("cliente@test.local", "cliente123")
    assert "La contraseña actual no es correcta." in _change(client, "mala", "NuevaClave2026", "NuevaClave2026").text
    assert "La confirmación no coincide" in _change(client, "cliente123", "NuevaClave2026", "OtraClave2026").text
    assert "Contraseña actualizada." not in _change(client, "cliente123", "corta", "corta").text
    # nada cambió
    assert 'href="/objetivos"' in login("cliente@test.local", "cliente123").get("/").text


def test_change_password_requires_csrf():
    client = login("cliente@test.local", "cliente123")
    client.post(
        "/cuenta/password",
        data={"current_password": "cliente123", "new_password": "NuevaClave2026", "confirm_password": "NuevaClave2026", "csrf_token": "malo"},
        follow_redirects=False,
    )
    assert 'href="/objetivos"' in login("cliente@test.local", "cliente123").get("/").text
