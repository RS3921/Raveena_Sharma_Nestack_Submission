"""Application factory: wires config, storage, auth service, error handling."""
import logging
import time

from flask import Flask, jsonify, render_template
from werkzeug.exceptions import HTTPException

from .auth import AuthService
from .config import Config, load_config
from .routes import bp, error
from .storage import Storage
from .validation import PrivilegeEscalationAttempt, ValidationError

log = logging.getLogger(__name__)


def create_app(config: Config | None = None, clock=time.time) -> Flask:
    cfg = config or load_config()
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = cfg.max_body_bytes   # backstop for chunked bodies
    app.config["MAX_BODY_BYTES"] = cfg.max_body_bytes
    app.config["PROPAGATE_EXCEPTIONS"] = False
    app.json.sort_keys = False

    store = Storage(cfg.database_path)
    app.extensions["store"] = store
    app.extensions["auth"] = AuthService(cfg, store, clock)
    app.register_blueprint(bp)

    @app.get("/")
    def playground():
        return render_template("index.html")

    @app.errorhandler(ValidationError)
    def _validation(exc):
        return error(400, exc.code, exc.message)

    @app.errorhandler(PrivilegeEscalationAttempt)
    def _escalation(_exc):
        return error(403, "forbidden", "Role cannot be set by clients")

    @app.errorhandler(HTTPException)
    def _http(exc):
        if exc.code == 413:                       # oversized body -> 400 per spec
            return error(400, "payload_too_large", "Request body too large")
        if exc.code == 400:
            return error(400, "bad_request", "Malformed request")
        return error(exc.code or 500, (exc.name or "error").lower().replace(" ", "_"))

    @app.errorhandler(Exception)
    def _unexpected(exc):
        log.exception("unhandled error")          # stack trace stays in server logs only
        return error(500, "internal_error", "Internal server error")

    @app.after_request
    def _headers(resp):
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; img-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'"
        )
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    return app
