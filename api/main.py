"""FastAPI application.

The model bundle is loaded once at startup and held on app.state.
joblib.load on a 23 MB bundle is far too slow to repeat per request.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from api import store
from api.config import get_settings
from api.errors import register_error_handlers
from api.limits import MaxBodySizeMiddleware
from api.routers import meta as meta_router
from api.routers import scan as scan_router
from api.routers import scans as scans_router
from api.routers import ui as ui_router
from api.scoring import load_bundle

logger = logging.getLogger(__name__)

MIN_BOOTSTRAP_KEY_LENGTH = 24


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    store.init_db(settings.db_path)
    store.ensure_internal_key(settings.db_path, settings.default_threshold)

    if settings.bootstrap_api_key:
        if len(settings.bootstrap_api_key) < MIN_BOOTSTRAP_KEY_LENGTH:
            raise RuntimeError(
                f"BOOTSTRAP_API_KEY must be at least {MIN_BOOTSTRAP_KEY_LENGTH}"
                " characters long. A weak key on a public API is worse than"
                " no key."
            )
        key_id = store.ensure_bootstrap_key(
            settings.db_path,
            settings.bootstrap_api_key,
            settings.bootstrap_api_key_name,
            settings.default_threshold,
        )
        if key_id is not None:
            logger.info(
                "Seeded bootstrap API key %r", settings.bootstrap_api_key_name
            )
        else:
            logger.info(
                "Bootstrap API key %r already exists; left as-is",
                settings.bootstrap_api_key_name,
            )

    # Raises on feature mismatch, which stops the app rather than
    # letting it serve meaningless predictions.
    app.state.bundle = load_bundle(settings.model_path)
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="Phishing Detector API",
        version="1.0.0",
        description=(
            "Static HTML phishing detection. Pages are downloaded but never "
            "rendered or executed."
        ),
        lifespan=lifespan,
    )
    register_error_handlers(app)
    app.add_middleware(MaxBodySizeMiddleware)
    app.include_router(scan_router.router)
    app.include_router(scans_router.router)
    app.include_router(meta_router.router)
    app.include_router(ui_router.router)
    app.mount("/static", StaticFiles(directory="api/static"), name="static")
    return app


app = create_app()
