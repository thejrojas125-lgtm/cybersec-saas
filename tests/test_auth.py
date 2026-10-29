from fastapi.testclient import TestClient

from app.core.database import SessionLocal, engine
from app.core.security import hash_password
from app.main import app
from app.models.base import Base
from app.models.target import Target
from app.models.user import User


def setup_function(function):
    """Crea una BD limpia con un admin y un cliente antes de cada test."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    # Limpiar tablas por orden de dependencia
    db.query(Target).delete()
    db.query(User).delete()
    db.commit()

    pw_hash, pw_salt = hash_password("admin123")
    admin = User(
        email="admin@test.local",
        password_hash=pw_hash,
        password_salt=pw_salt,
        is_admin=True,
        is_active=True,
    )
    db.add(admin)

    pw_hash2, pw_salt2 = hash_password("cliente123")
    cliente = User(
        email="cliente@test.local",
        password_hash=pw_hash2,
        password_salt=pw_salt2,
        is_admin=False,
        is_active=True,
    )
    db.add(cliente)
    db.commit()
    db.close()


def teardown_function(function):
    Base.metadata.drop_all(bind=engine)


def client_logged_in(email: str, password: str) -> TestClient:
    """Devuelve un TestClient con sesión iniciada como el usuario dado."""
    import re
    client = TestClient(app)
    # Obtener csrf_token válido
    resp = client.get("/login", follow_redirects=False)
    match = re.search(r'name="csrf_token" value="([^"]+)"', resp.text)
    assert match, "No se encontró csrf_token en el HTML de login"
    token = match.group(1)
    resp = client.post("/login", data={"email": email, "password": password, "csrf_token": token}, follow_redirects=False)
    assert resp.status_code in (302, 200), f"login falló: {resp.status_code} {resp.text}"
    return client


# -------------------- Login --------------------

def test_login_page_loads():
    client = TestClient(app)
    resp = client.get("/login")
    assert resp.status_code == 200
    assert "Iniciar sesión" in resp.text


def test_login_valid_credentials():
    client = TestClient(app)
    resp = client.get("/login", follow_redirects=False)
    import re
    match = re.search(r'name="csrf_token" value="([^"]+)"', resp.text)
    token = match.group(1)
    resp = client.post(
        "/login",
        data={"email": "admin@test.local", "password": "admin123", "csrf_token": token},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/"


def test_login_invalid_credentials():
    client = TestClient(app)
    resp = client.get("/login", follow_redirects=False)
    import re
    match = re.search(r'name="csrf_token" value="([^"]+)"', resp.text)
    token = match.group(1)
    resp = client.post("/login", data={"email": "admin@test.local", "password": "wrong", "csrf_token": token}, follow_redirects=False)
    assert resp.status_code == 400
    assert "Credenciales inválidas" in resp.text


def test_login_unknown_user():
    client = TestClient(app)
    resp = client.get("/login", follow_redirects=False)
    import re
    match = re.search(r'name="csrf_token" value="([^"]+)"', resp.text)
    token = match.group(1)
    resp = client.post("/login", data={"email": "noexiste@test.local", "password": "x", "csrf_token": token}, follow_redirects=False)
    assert resp.status_code == 400


def test_logout_clears_session():
    client = TestClient(app)
    # Obtener csrf_token válido de la sesión
    resp = client.get("/login", follow_redirects=False)
    import re
    match = re.search(r'name="csrf_token" value="([^"]+)"', resp.text)
    assert match, "No se encontró csrf_token en el HTML de login"
    token = match.group(1)

    # Hacer login
    resp = client.post("/login", data={"email": "admin@test.local", "password": "admin123", "csrf_token": token}, follow_redirects=False)
    assert resp.status_code == 302

    # Obtener nuevo csrf_token tras login
    resp = client.get("/login", follow_redirects=False)
    match = re.search(r'name="csrf_token" value="([^"]+)"', resp.text)
    token = match.group(1)

    resp = client.post("/logout", data={"csrf_token": token}, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"

    # Tras logout, / debe redirigir a /login
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


def test_logout_rejects_invalid_csrf():
    client = TestClient(app)
    # Login primero
    resp = client.get("/login", follow_redirects=False)
    import re
    match = re.search(r'name="csrf_token" value="([^"]+)"', resp.text)
    token = match.group(1)
    client.post("/login", data={"email": "admin@test.local", "password": "admin123", "csrf_token": token}, follow_redirects=False)

    # Logout con token inválido
    resp = client.post("/logout", data={"csrf_token": "invalido"}, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


def test_login_rejects_invalid_csrf():
    client = TestClient(app)
    resp = client.post("/login", data={"email": "admin@test.local", "password": "admin123", "csrf_token": "invalido"}, follow_redirects=False)
    assert resp.status_code == 302  # redirect de vuelta a /login por CSRF fallido


# -------------------- Rate limiting --------------------

def test_login_rate_limit_blocks_after_max_attempts():
    client = TestClient(app)
    email = "rate@test.local"

    # Crear usuario para que exista (aunque la contraseña esté mal, el email existe en el rate limiter)
    # No necesitamos que el usuario exista; el rate limiter actúa sobre el email enviado
    for i in range(5):
        resp = client.get("/login", follow_redirects=False)
        import re
        match = re.search(r'name="csrf_token" value="([^"]+)"', resp.text)
        token = match.group(1)
        resp = client.post(
            "/login",
            data={"email": email, "password": "wrong", "csrf_token": token},
            follow_redirects=False,
        )
        assert resp.status_code == 400, f"Intento {i+1} esperaba 400, obtuvo {resp.status_code}"

    # El 6to intento debe ser bloqueado con 429
    resp = client.get("/login", follow_redirects=False)
    match = re.search(r'name="csrf_token" value="([^"]+)"', resp.text)
    token = match.group(1)
    resp = client.post(
        "/login",
        data={"email": email, "password": "wrong", "csrf_token": token},
        follow_redirects=False,
    )
    assert resp.status_code == 429
    assert "Demasiados intentos" in resp.text


# -------------------- Rutas HTML protegidas --------------------

def test_dashboard_requires_login():
    client = TestClient(app)
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


def test_admin_requires_login():
    client = TestClient(app)
    resp = client.get("/admin", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


def test_dashboard_admin_sees_all_targets():
    db = SessionLocal()
    t1 = Target(name="Target Admin", url="https://admin.example.com", owner_id=1)
    t2 = Target(name="Target Cliente", url="https://cliente.example.com", owner_id=2)
    db.add_all([t1, t2])
    db.commit()
    db.close()

    client = client_logged_in("admin@test.local", "admin123")
    resp = client.get("/objetivos")
    assert resp.status_code == 200
    assert "Target Admin" in resp.text
    assert "Target Cliente" in resp.text


def test_dashboard_cliente_sees_only_own_targets():
    db = SessionLocal()
    t1 = Target(name="Target Admin", url="https://admin.example.com", owner_id=1)
    t2 = Target(name="Target Cliente", url="https://cliente.example.com", owner_id=2)
    db.add_all([t1, t2])
    db.commit()
    db.close()

    client = client_logged_in("cliente@test.local", "cliente123")
    resp = client.get("/objetivos")
    assert resp.status_code == 200
    assert "Target Cliente" in resp.text
    assert "Target Admin" not in resp.text


def test_target_detail_cliente_cannot_see_others():
    db = SessionLocal()
    t1 = Target(name="Target Admin", url="https://admin.example.com", owner_id=1)
    db.add(t1)
    db.commit()
    target_id = t1.id
    db.close()

    client = client_logged_in("cliente@test.local", "cliente123")
    resp = client.get(f"/targets/{target_id}/view")
    assert resp.status_code == 403


# -------------------- API protegida --------------------

def test_api_users_requires_auth():
    client = TestClient(app)
    resp = client.post(
        "/users",
        json={"email": "nuevo@test.local", "password": "x", "is_admin": False},
    )
    assert resp.status_code == 401


def test_api_users_admin_can_create():
    client = client_logged_in("admin@test.local", "admin123")
    resp = client.post(
        "/users",
        json={"email": "nuevo@test.local", "password": "NuevaPass123", "is_admin": False},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["email"] == "nuevo@test.local"
    assert body["is_admin"] is False


def test_api_users_rejects_weak_password():
    client = client_logged_in("admin@test.local", "admin123")
    resp = client.post(
        "/users",
        json={"email": "debil@test.local", "password": "corta", "is_admin": False},
    )
    assert resp.status_code == 400


def test_api_targets_filters_by_owner():
    db = SessionLocal()
    t1 = Target(name="T1", url="https://t1.example.com", owner_id=1)
    t2 = Target(name="T2", url="https://t2.example.com", owner_id=2)
    db.add_all([t1, t2])
    db.commit()
    t2_id = t2.id
    db.close()

    client = client_logged_in("cliente@test.local", "cliente123")
    resp = client.get("/targets")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 1
    assert data["items"][0]["name"] == "T2"
    assert data["items"][0]["owner_id"] == 2
    assert data["items"][0]["id"] == t2_id


def test_api_trigger_scan_creates_run_and_findings():
    from app.models.finding import Finding
    from app.models.scan_run import ScanRun

    db = SessionLocal()
    t = Target(name="Scan Target", url="https://example.com", owner_id=2)
    db.add(t)
    db.commit()
    target_id = t.id
    db.close()

    client = client_logged_in("cliente@test.local", "cliente123")
    resp = client.post(f"/targets/{target_id}/scan", follow_redirects=False)
    assert resp.status_code == 202
    body = resp.json()
    assert body["accepted"] is True
    assert body["target_id"] == target_id

    # Verificar que se creó un ScanRun con hallazgos
    db = SessionLocal()
    scans = db.query(ScanRun).filter(ScanRun.target_id == target_id).all()
    assert len(scans) == 1
    assert scans[0].status == "done"
    findings = db.query(Finding).filter(Finding.scan_run_id == scans[0].id).all()
    assert len(findings) > 0
    for f in findings:
        assert f.severity in ("low", "medium", "high", "critical")
        assert f.title
        assert f.description
        assert f.remediation
    db.close()


def test_api_trigger_scan_requires_ownership():
    db = SessionLocal()
    t = Target(name="Admin Target", url="https://admin.example.com", owner_id=1)
    db.add(t)
    db.commit()
    target_id = t.id
    db.close()

    # Cliente intenta escanear target del admin (id=1)
    client = client_logged_in("cliente@test.local", "cliente123")
    resp = client.post(f"/targets/{target_id}/scan", follow_redirects=False)
    assert resp.status_code == 403


def test_api_download_report_pdf():
    db = SessionLocal()
    t = Target(name="Reporte Target", url="https://example.com", owner_id=2)
    db.add(t)
    db.commit()
    target_id = t.id
    db.close()

    client = client_logged_in("cliente@test.local", "cliente123")
    # Lanzar scan para que haya hallazgos
    resp = client.post(f"/targets/{target_id}/scan", follow_redirects=False)
    assert resp.status_code == 202

    # Descargar reporte PDF
    resp = client.get(f"/targets/{target_id}/report")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert "attachment" in resp.headers.get("content-disposition", "")
    assert resp.content.startswith(b"%PDF")  # firma de archivo PDF


# -------------------- SSRF --------------------

def test_create_target_rejects_localhost():
    client = client_logged_in("admin@test.local", "admin123")
    resp = client.post(
        "/targets",
        json={"name": "Localhost", "url": "http://localhost:8000", "owner_id": 1},
        follow_redirects=False,
    )
    assert resp.status_code == 400


def test_create_target_rejects_private_ip():
    client = client_logged_in("admin@test.local", "admin123")
    resp = client.post(
        "/targets",
        json={"name": "Private IP", "url": "http://192.168.1.1", "owner_id": 1},
        follow_redirects=False,
    )
    assert resp.status_code == 400


def test_create_target_rejects_link_local():
    client = client_logged_in("admin@test.local", "admin123")
    resp = client.post(
        "/targets",
        json={"name": "Link Local", "url": "http://169.254.169.254", "owner_id": 1},
        follow_redirects=False,
    )
    assert resp.status_code == 400


def test_create_target_accepts_public_url():
    client = client_logged_in("admin@test.local", "admin123")
    resp = client.post(
        "/targets",
        json={"name": "Public", "url": "https://example.com", "owner_id": 1},
        follow_redirects=False,
    )
    assert resp.status_code == 201


# -------------------- JWT --------------------

def test_jwt_token_endpoint():
    client = TestClient(app)
    resp = client.post(
        "/auth/token",
        data={"username": "admin@test.local", "password": "admin123"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "access_token" in body
    assert body["token_type"] == "bearer"


def test_jwt_token_wrong_password():
    client = TestClient(app)
    resp = client.post(
        "/auth/token",
        data={"username": "admin@test.local", "password": "wrong"},
    )
    assert resp.status_code == 401


def test_jwt_protected_endpoint_with_token():
    client = TestClient(app)
    # Obtener token
    resp = client.post(
        "/auth/token",
        data={"username": "admin@test.local", "password": "admin123"},
    )
    token = resp.json()["access_token"]

    # Crear un target primero (necesitamos autenticación de sesión para eso, pero usamos API directa)
    # Usamos la sesión de HTML para crear un target
    resp = client.get("/login", follow_redirects=False)
    import re
    match = re.search(r'name="csrf_token" value="([^"]+)"', resp.text)
    csrf_token = match.group(1)
    client.post(
        "/login",
        data={"email": "admin@test.local", "password": "admin123", "csrf_token": csrf_token},
        follow_redirects=False,
    )

    resp = client.post(
        "/targets",
        json={"name": "JWT Target", "url": "https://example.com", "owner_id": 1},
    )
    target_id = resp.json()["id"]

    # Acceder a endpoint protegido con JWT
    resp = client.get(
        f"/targets/{target_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "JWT Target"


def test_jwt_protected_endpoint_without_token():
    client = TestClient(app)
    resp = client.get("/targets/1")
    assert resp.status_code == 401


# -------------------- Paginación --------------------

def test_targets_pagination():
    client = client_logged_in("admin@test.local", "admin123")
    # Crear varios targets (usar example.com que resuelve en DNS)
    for i in range(5):
        client.post(
            "/targets",
            json={"name": f"Target {i}", "url": "https://example.com", "owner_id": 1},
        )

    resp = client.get("/targets?page=1&page_size=2")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 2
    assert data["page"] == 1
    assert data["page_size"] == 2
    assert data["total"] == 5
    assert data["pages"] == 3


# -------------------- Cambio de estado de hallazgo --------------------

def test_update_finding_status():
    db = SessionLocal()
    t = Target(name="Status Target", url="https://example.com", owner_id=2)
    db.add(t)
    db.commit()
    target_id = t.id
    db.close()

    client = client_logged_in("cliente@test.local", "cliente123")
    # Lanzar scan
    resp = client.post(f"/targets/{target_id}/scan", follow_redirects=False)
    assert resp.status_code == 202

    # Obtener el finding creado
    db = SessionLocal()
    from app.models.finding import Finding
    from app.models.scan_run import ScanRun
    scan = db.query(ScanRun).filter(ScanRun.target_id == target_id).first()
    finding = db.query(Finding).filter(Finding.scan_run_id == scan.id).first()
    finding_id = finding.id
    assert finding.status == "pending"
    db.close()

    # Cambiar a resolved
    resp = client.patch(
        f"/findings/{finding_id}/status",
        json={"status": "resolved"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "resolved"

    # Intentar estado inválido
    resp = client.patch(
        f"/findings/{finding_id}/status",
        json={"status": "invalido"},
    )
    assert resp.status_code == 400

    # Cliente no puede cambiar finding de otro usuario
    db = SessionLocal()
    t2 = Target(name="Admin Target", url="https://admin.example.com", owner_id=1)
    db.add(t2)
    db.commit()
    t2_id = t2.id
    db.close()

    resp = client.post(f"/targets/{t2_id}/scan", follow_redirects=False)
    assert resp.status_code == 403
