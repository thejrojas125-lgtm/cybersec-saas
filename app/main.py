import os
import time
import uuid

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import text
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app import ui
from app.api import routes
from app.api.deps import DbSession, get_current_user_html, require_auth_html
from app.core import config
from app.core.audit import record_audit
from app.core.config import SECRET_KEY
from app.core.csrf import generate_csrf_token, validate_csrf_token
from app.core.database import SessionLocal, engine, get_db
from app.core.logging import logger, request_id_var
from app.core.rate_limit import check_rate_limit, record_failed_attempt, reset_attempts
from app.core.security import (
    WeakPasswordError,
    get_user_by_email,
    hash_password,
    validate_password_strength,
    verify_password,
)
from app.core.security_headers import apply_security_headers
from app.core.ssrf import UnsafeTargetError, validate_target_url
from app.core.verification import (
    check_domain_ownership,
    mark_verified,
    new_verification_token,
    verification_instructions,
)
from app.models.base import Base
from app.models.target import Target
from app.models.user import User
from worker.tasks import execute_scan, run_scan

app = FastAPI(
    title="Cybersec SaaS",
    version="1.0.0",
    debug=config.DEBUG,
    docs_url="/docs" if config.DOCS_ENABLED else None,
    redoc_url="/redoc" if config.DOCS_ENABLED else None,
    openapi_url="/openapi.json" if config.DOCS_ENABLED else None,
)

if config.TRUSTED_HOSTS:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=config.TRUSTED_HOSTS)

https_only = config.IS_PRODUCTION
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    https_only=https_only,
    same_site="lax",
    max_age=60 * 60 * 24 * 7,
)

allowed_origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
if not allowed_origins and not config.IS_PRODUCTION:
    allowed_origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_context_middleware(request: Request, call_next):
    """Añade request ID, mide duración y aplica cabeceras de seguridad."""
    rid = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:16]
    token = request_id_var.set(rid)
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        request_id_var.reset(token)
        raise
    duration_ms = (time.perf_counter() - started) * 1000
    response.headers["X-Request-ID"] = rid
    response.headers["X-Response-Time-ms"] = f"{duration_ms:.1f}"
    apply_security_headers(response, request.url.path, hsts=config.IS_PRODUCTION)
    logger.info(
        "request",
        extra={"method": request.method, "path": request.url.path, "status": response.status_code, "duration_ms": round(duration_ms, 1)},
    )
    request_id_var.reset(token)
    return response


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Devuelve 500 sin filtrar detalles internos en producción."""
    logger.exception("unhandled_exception", extra={"path": request.url.path, "error": str(exc)})
    if request.url.path.startswith("/api") or request.headers.get("accept", "").startswith("application/json"):
        return JSONResponse(status_code=500, content={"detail": "Error interno del servidor"})
    return HTMLResponse("<h1>500</h1><p>Error interno del servidor</p>", status_code=500)

app.include_router(routes.router)

try:
    from prometheus_fastapi_instrumentator import Instrumentator
    Instrumentator().instrument(app).expose(app, endpoint="/metrics")
except Exception:  # noqa: BLE001
    logger.warning("prometheus_instrumentator_no_disponible")

# Crear tablas solo en desarrollo; en producción las migraciones Alembic son la fuente de verdad
if not config.IS_PRODUCTION:
    Base.metadata.create_all(bind=engine)

# Bootstrap de administrador inicial (opcional, vía variables de entorno)
_admin_email = os.getenv("ADMIN_EMAIL")
_admin_password = os.getenv("ADMIN_PASSWORD")
if _admin_email and _admin_password:
    try:
        validate_password_strength(_admin_password)
    except WeakPasswordError as exc:
        logger.error("admin_bootstrap_no_creado", extra={"error": str(exc)})
    else:
        _db = SessionLocal()
        try:
            if not get_user_by_email(_db, _admin_email):
                _h, _s = hash_password(_admin_password)
                _db.add(User(email=_admin_email.strip().lower(), password_hash=_h, password_salt=_s, is_admin=True, is_active=True))
                _db.commit()
                logger.info("admin_bootstrap_creado", extra={"email": _admin_email})
        finally:
            _db.close()

templates = Jinja2Templates(directory="app/templates")
app.mount("/static", StaticFiles(directory="app/static"), name="static")

ui.register_filters(templates.env)


def error_page(request: Request, status_code: int, title: str, message: str):
    ctx = common_context(request)
    ctx.update({"user": get_current_user_html(request), "title": title, "message": message})
    return templates.TemplateResponse("error.html", ctx, status_code=status_code)


def flash(request: Request, category: str, message: str):
    """Guarda un mensaje flash en la sesión para mostrarlo en la próxima respuesta."""
    flashes = request.session.get("flashes", [])
    flashes.append([category, message])
    request.session["flashes"] = flashes


def get_flashes(request: Request):
    """Devuelve y limpia los mensajes flash de la sesión."""
    flashes = request.session.pop("flashes", [])
    return flashes


def common_context(request: Request) -> dict:
    """Contexto común para todas las vistas HTML: csrf_token y flashes."""
    return {
        "request": request,
        "csrf_token": request.session.get("csrf_token", ""),
        "flashes": get_flashes(request),
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/ready")
def ready(db: DbSession):
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ready"}
    except Exception:
        return HTMLResponse("not ready", status_code=503)


# ---- Auth HTML ----

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    ctx = common_context(request)
    ctx["error"] = None
    ctx["csrf_token"] = generate_csrf_token(request)
    return templates.TemplateResponse("login.html", ctx)


@app.post("/login", response_class=HTMLResponse)
def login(request: Request, email: str = Form(...), password: str = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    if not validate_csrf_token(request, csrf_token):
        logger.warning("csrf_invalido", extra={"ruta": "/login"})
        return RedirectResponse(url="/login", status_code=302)

    email = (email or "").strip().lower()
    check_rate_limit(email)

    user = get_user_by_email(db, email)
    if not user or not verify_password(password, user.password_hash, user.password_salt):
        record_failed_attempt(email)
        logger.warning("login_fallido", extra={"email": email, "origen": "html"})
        generate_csrf_token(request)
        ctx = common_context(request)
        ctx["error"] = "Credenciales inválidas"
        ctx["csrf_token"] = request.session.get("csrf_token", "")
        return templates.TemplateResponse("login.html", ctx, status_code=400)

    if not user.is_active:
        ctx = common_context(request)
        ctx["error"] = "La cuenta está desactivada"
        return templates.TemplateResponse("login.html", ctx, status_code=403)

    reset_attempts(email)
    request.session["user_id"] = user.id
    request.session["user_email"] = user.email
    request.session["is_admin"] = user.is_admin
    flash(request, "success", f"Bienvenido, {user.email}")
    record_audit(
        db,
        action="login_ok",
        user_id=user.id,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    logger.info("login_ok", extra={"email": email, "origen": "html", "user_id": user.id})
    return RedirectResponse(url="/", status_code=302)


@app.post("/logout")
def logout(request: Request, csrf_token: str = Form(...)):
    if not validate_csrf_token(request, csrf_token):
        return RedirectResponse(url="/login", status_code=302)
    user_id = request.session.get("user_id")
    request.session.clear()
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("session")
    logger.info("logout", extra={"user_id": user_id})
    return response


# ---- HTML: cliente panel ----

def _page_context(request: Request, db, severity: str | None = None):
    """Usuario autenticado, objetivos visibles y datos de resumen. Devuelve (user, redirect, ctx)."""
    user = get_current_user_html(request)
    redirect = require_auth_html(request, user)
    if redirect:
        return None, redirect, None
    query = db.query(Target)
    if not user.is_admin:
        query = query.filter(Target.owner_id == user.id)
    targets = query.all()
    summaries, last_scan = ui.target_summaries(targets)
    ordered = ui.sorted_by_risk(targets, summaries)
    totals = ui.severity_totals(summaries)
    ctx = common_context(request)
    ctx.update(
        {
            "user": user,
            "targets": ordered,
            "summaries": summaries,
            "totals": totals,
            "stats": {
                "total_targets": len(ordered),
                "critical_findings": totals["critical"],
                "last_scan": last_scan,
                "worst": ordered[0] if totals["critical"] else None,
            },
        }
    )
    return user, None, ctx


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: DbSession):
    _, redirect, ctx = _page_context(request, db)
    if redirect:
        return redirect
    ctx.update(
        {
            "bar": ui.stacked_bar(ctx["totals"]),
            "attention": [t for t in ctx["targets"] if ctx["summaries"][t.id]["total"]][:5],
            "recent": ui.recent_scans(ctx["targets"], 5),
        }
    )
    return templates.TemplateResponse("index.html", ctx)


@app.get("/objetivos", response_class=HTMLResponse)
def targets_page(request: Request, db: DbSession):
    _, redirect, ctx = _page_context(request, db)
    if redirect:
        return redirect
    return templates.TemplateResponse("objetivos.html", ctx)


@app.get("/hallazgos", response_class=HTMLResponse)
def findings_page(request: Request, db: DbSession, severidad: str = ""):
    _, redirect, ctx = _page_context(request, db)
    if redirect:
        return redirect
    selected = severidad if severidad in ui.SEVERITIES else ""
    ctx.update(
        {
            "items": ui.open_findings(ctx["targets"], ctx["summaries"], selected or None),
            "selected": selected,
        }
    )
    return templates.TemplateResponse("hallazgos.html", ctx)


@app.get("/escaneos", response_class=HTMLResponse)
def scans_page(request: Request, db: DbSession):
    _, redirect, ctx = _page_context(request, db)
    if redirect:
        return redirect
    ctx["rows"] = ui.recent_scans(ctx["targets"], 100)
    return templates.TemplateResponse("escaneos.html", ctx)


@app.get("/informes", response_class=HTMLResponse)
def reports_page(request: Request, db: DbSession):
    _, redirect, ctx = _page_context(request, db)
    if redirect:
        return redirect
    return templates.TemplateResponse("informes.html", ctx)


@app.get("/cuenta", response_class=HTMLResponse)
def account_page(request: Request, db: DbSession):
    user = get_current_user_html(request)
    redirect = require_auth_html(request, user)
    if redirect:
        return redirect
    ctx = common_context(request)
    ctx["user"] = user
    return templates.TemplateResponse("cuenta.html", ctx)


@app.post("/cuenta/password", response_class=HTMLResponse)
def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    csrf_token: str = Form(...),
    db: DbSession = None,
):
    if not validate_csrf_token(request, csrf_token):
        return RedirectResponse(url="/cuenta", status_code=302)
    user = get_current_user_html(request)
    redirect = require_auth_html(request, user)
    if redirect:
        return redirect

    limiter_key = f"pwchange:{user.id}"
    check_rate_limit(limiter_key)
    back = RedirectResponse(url="/cuenta", status_code=302)
    if not verify_password(current_password, user.password_hash, user.password_salt):
        record_failed_attempt(limiter_key)
        flash(request, "error", "La contraseña actual no es correcta.")
        return back
    if new_password != confirm_password:
        flash(request, "error", "La confirmación no coincide con la nueva contraseña.")
        return back
    try:
        validate_password_strength(new_password)
    except WeakPasswordError as exc:
        flash(request, "error", str(exc))
        return back

    # El usuario de la sesión viene de otra conexión: se vuelve a cargar en la sesión de esta petición.
    db_user = db.get(User, user.id)
    db_user.password_hash, db_user.password_salt = hash_password(new_password)
    db.commit()
    reset_attempts(limiter_key)
    record_audit(
        db,
        action="password_changed",
        user_id=user.id,
        target_type="user",
        target_id=user.id,
        ip=request.client.host if request.client else None,
    )
    logger.info("password_cambiada", extra={"user_id": user.id})
    flash(request, "success", "Contraseña actualizada.")
    return back


@app.get("/targets/{target_id}/view", response_class=HTMLResponse)
def target_detail(request: Request, target_id: int, db: DbSession):
    user = get_current_user_html(request)
    redirect = require_auth_html(request, user)
    if redirect:
        return redirect

    target = db.get(Target, target_id)
    if not target:
        return error_page(request, 404, "No encontrado", "El recurso que buscas no existe.")
    if not user.is_admin and target.owner_id != user.id:
        return error_page(request, 403, "Sin acceso", "No tienes acceso a este objetivo.")

    ctx = common_context(request)
    instructions = None
    if target.verified_at is None and target.verification_token:
        try:
            instructions = verification_instructions(target.url, target.verification_token)
        except UnsafeTargetError:
            instructions = None
    ctx.update({
        "target": target,
        "user": user,
        "scans": sorted(target.scans, key=lambda s: s.id, reverse=True),
        "instructions": instructions,
        "verification_required": config.REQUIRE_TARGET_VERIFICATION,
    })
    return templates.TemplateResponse("target.html", ctx)


def _owned_target_or_error(request: Request, target_id: int, db, csrf_token: str):
    """Valida CSRF, sesión y propiedad. Devuelve (user, target, respuesta_de_error)."""
    back = RedirectResponse(url=f"/targets/{target_id}/view", status_code=302)
    if not validate_csrf_token(request, csrf_token):
        return None, None, back
    user = get_current_user_html(request)
    redirect = require_auth_html(request, user)
    if redirect:
        return None, None, redirect
    target = db.get(Target, target_id)
    if not target:
        return None, None, error_page(request, 404, "No encontrado", "El recurso que buscas no existe.")
    if not user.is_admin and target.owner_id != user.id:
        return None, None, error_page(request, 403, "Sin acceso", "No tienes acceso a este objetivo.")
    return user, target, None


@app.post("/targets/{target_id}/verification-html", response_class=HTMLResponse)
def request_verification_html(request: Request, target_id: int, csrf_token: str = Form(...), db: DbSession = None):
    _, target, error = _owned_target_or_error(request, target_id, db, csrf_token)
    if error:
        return error
    if target.verified_at is None and not target.verification_token:
        target.verification_token = new_verification_token()
        db.commit()
    return RedirectResponse(url=f"/targets/{target_id}/view", status_code=302)


@app.post("/targets/{target_id}/verify-html", response_class=HTMLResponse)
def verify_target_html(request: Request, target_id: int, csrf_token: str = Form(...), db: DbSession = None):
    _, target, error = _owned_target_or_error(request, target_id, db, csrf_token)
    if error:
        return error
    if not target.verification_token:
        flash(request, "error", "Genera primero el token de verificación.")
    else:
        try:
            ok = check_domain_ownership(target.url, target.verification_token)
        except UnsafeTargetError:
            ok = False
        if ok:
            mark_verified(target)
            db.commit()
            flash(request, "success", "Dominio verificado. Ya puedes ejecutar escaneos.")
        else:
            flash(request, "error", "No encontramos el token en DNS ni en /.well-known/. Los cambios de DNS pueden tardar.")
    return RedirectResponse(url=f"/targets/{target_id}/view", status_code=302)


@app.post("/targets/{target_id}/scan-html", response_class=HTMLResponse)
def trigger_scan_html(request: Request, target_id: int, csrf_token: str = Form(...), db: DbSession = None):
    if not validate_csrf_token(request, csrf_token):
        return RedirectResponse(url=f"/targets/{target_id}/view", status_code=302)
    user = get_current_user_html(request)
    redirect = require_auth_html(request, user)
    if redirect:
        return redirect

    target = db.get(Target, target_id)
    if not target:
        return error_page(request, 404, "No encontrado", "El recurso que buscas no existe.")
    if not user.is_admin and target.owner_id != user.id:
        return error_page(request, 403, "Sin acceso", "No tienes acceso a este objetivo.")

    try:
        validate_target_url(target.url)
    except Exception:
        return error_page(request, 400, "URL no permitida", "La URL de este objetivo no está permitida para escaneos.")

    if config.REQUIRE_TARGET_VERIFICATION and target.verified_at is None:
        flash(request, "error", "Verifica la propiedad del dominio antes de escanear.")
        return RedirectResponse(url=f"/targets/{target_id}/view", status_code=302)

    enqueued = False
    if config.SCAN_ASYNC:
        try:
            run_scan.delay(target_id)
            enqueued = True
        except Exception:  # noqa: BLE001 - sin broker/worker, ejecutar síncrono
            pass

    if enqueued:
        flash(request, "success", "Escaneo en cola; los resultados aparecerán al finalizar.")
        return RedirectResponse(url=f"/targets/{target_id}/view", status_code=302)

    result = execute_scan(target_id)
    if "error" in result:
        flash(request, "error", f"Error al ejecutar el escaneo: {result['error']}")
    else:
        flash(request, "success", f"Escaneo completado: {result.get('findings', 0)} hallazgo(s) encontrado(s)")
    return RedirectResponse(url=f"/targets/{target_id}/view", status_code=302)


# ---- HTML: administrador panel ----

@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request, db: DbSession):
    user = get_current_user_html(request)
    redirect = require_auth_html(request, user)
    if redirect:
        return redirect
    if not user.is_admin:
        return error_page(request, 403, "Acceso restringido", "Solo los administradores pueden ver este panel.")

    users = db.query(User).all()
    targets = db.query(Target).all()

    total_users = len(users)
    total_admins = sum(1 for u in users if u.is_admin)
    total_targets = len(targets)

    total_critical_findings = 0
    for t in targets:
        scans = sorted(t.scans, key=lambda s: s.id)
        if scans:
            total_critical_findings += ui.filtro_conteo_abiertos(scans[-1].findings)["critical"]

    stats = {
        "total_users": total_users,
        "total_admins": total_admins,
        "total_targets": total_targets,
        "total_critical_findings": total_critical_findings,
    }

    ctx = common_context(request)
    ctx.update({"users": users, "targets": targets, "user": user, "stats": stats, "owners": {u.id: u.email for u in users}})
    return templates.TemplateResponse("admin.html", ctx)


# ---- HTML: administrador - gestión ----

@app.post("/admin/users", response_class=HTMLResponse)
def admin_create_user(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    is_admin: str = Form("false"),
    csrf_token: str = Form(...),
    db: DbSession = None,
):
    if not validate_csrf_token(request, csrf_token):
        return RedirectResponse(url="/admin", status_code=302)
    user = get_current_user_html(request)
    redirect = require_auth_html(request, user)
    if redirect:
        return redirect
    if not user or not user.is_admin:
        return error_page(request, 403, "Acceso restringido", "Solo los administradores pueden realizar esta acción.")

    owned = db is None
    if owned:
        db = SessionLocal()
    try:
        email = (email or "").strip().lower()
        if "@" not in email:
            flash(request, "error", "Email inválido")
            return RedirectResponse(url="/admin", status_code=302)
        try:
            validate_password_strength(password)
        except WeakPasswordError as exc:
            flash(request, "error", str(exc))
            return RedirectResponse(url="/admin", status_code=302)
        existing = get_user_by_email(db, email)
        if existing:
            flash(request, "error", "El correo ya está registrado")
            return RedirectResponse(url="/admin", status_code=302)
        pwd_hash, pwd_salt = hash_password(password)
        new_user = User(
            email=email,
            password_hash=pwd_hash,
            password_salt=pwd_salt,
            is_admin=(is_admin == "true"),
            is_active=True,
        )
        db.add(new_user)
        db.commit()
        flash(request, "success", f"Usuario {email} creado")
        record_audit(
            db,
            action="user_created",
            user_id=user.id,
            target_type="user",
            target_id=new_user.id,
            ip=request.client.host if request.client else None,
            details={"email": email, "is_admin": new_user.is_admin},
        )
        logger.info("usuario_creado_admin_ui", extra={"actor_id": user.id, "nuevo_usuario_id": new_user.id})
    finally:
        if owned:
            db.close()
    return RedirectResponse(url="/admin", status_code=302)


@app.post("/admin/targets", response_class=HTMLResponse)
def admin_create_target(
    request: Request,
    name: str = Form(...),
    url: str = Form(...),
    owner_id: int = Form(...),
    csrf_token: str = Form(...),
    db: DbSession = None,
):
    if not validate_csrf_token(request, csrf_token):
        return RedirectResponse(url="/admin", status_code=302)
    user = get_current_user_html(request)
    redirect = require_auth_html(request, user)
    if redirect:
        return redirect
    if not user or not user.is_admin:
        return error_page(request, 403, "Acceso restringido", "Solo los administradores pueden realizar esta acción.")

    try:
        validate_target_url(url)
    except Exception:
        flash(request, "error", "URL no permitida")
        return RedirectResponse(url="/admin", status_code=302)

    owned = db is None
    if owned:
        db = SessionLocal()
    try:
        if not db.get(User, owner_id):
            flash(request, "error", "Propietario no encontrado")
            return RedirectResponse(url="/admin", status_code=302)
        target = Target(name=name, url=url, owner_id=owner_id, is_active=True)
        db.add(target)
        db.commit()
        flash(request, "success", f"Objetivo {name} creado")
        record_audit(
            db,
            action="target_created",
            user_id=user.id,
            target_type="target",
            target_id=target.id,
            ip=request.client.host if request.client else None,
            details={"name": name, "url": url, "owner_id": owner_id},
        )
    finally:
        if owned:
            db.close()
    return RedirectResponse(url="/admin", status_code=302)


# ---- Cron externo (free tier: sin Celery beat) ----

@app.post("/cron/scan-next")
def cron_scan_next(request: Request, db: DbSession):
    """Escanea el siguiente target activo con el escaneo más antiguo (o sin escaneo).
    Pensado para cron externo (p.ej. cron-job.org) en despliegues sin worker Celery."""
    token = request.headers.get("X-Cron-Token", "")
    if not token and request.headers.get("Authorization", "").startswith("Bearer "):
        token = request.headers["Authorization"].replace("Bearer ", "", 1)
    if not config.CRON_TOKEN or not token or token != config.CRON_TOKEN:
        raise HTTPException(status_code=401, detail="Token inválido")

    targets = db.query(Target).filter(Target.is_active == True).all()  # noqa: E712
    if not targets:
        return {"scanned": False, "reason": "no hay targets activos"}

    selected = None
    selected_time = None
    for t in targets:
        times = [s.started_at for s in t.scans if s.started_at]
        latest = max(times) if times else None
        if latest is None:
            selected = t
            break
        if selected_time is None or latest < selected_time:
            selected_time = latest
            selected = t

    if selected is None:
        return {"scanned": False, "reason": "todos los targets están al día"}

    result = execute_scan(selected.id)
    return {"scanned": True, "target_id": selected.id, "result": result}
