import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from src.config import settings
from src.app.auth.router import router as auth_router
from src.app.profile.router import router as profile_router
from src.app.admin.router import router as admin_router
from src.app.dependencies import _rate_limiter
from src.app.middleware.exception_handler import (
    register_exception_handlers,
)
from src.app.middleware.request_context import (
    RequestContextMiddleware,
)
from src.external.database.engine import engine
from src.external.tasks.cleanup import TokenCleanupTask

logger = logging.getLogger(__name__)

_cleanup_task = TokenCleanupTask(interval_seconds=3600)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        {
            "event": "app_starting",
            "environment": settings.ENVIRONMENT.value,
            "version": settings.APP_VERSION,
        }
    )
    await _rate_limiter.start()
    await _cleanup_task.start()

    yield

    await _cleanup_task.stop()
    await _rate_limiter.stop()
    await engine.dispose()
    logger.info({"event": "app_shutdown"})


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="Authentication & Authorization Service",
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=(
            ["*"] if not settings.is_production
            else [settings.BASE_URL]
        ),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(RequestContextMiddleware)

    register_exception_handlers(app)

    api_v1 = "/api/v1"
    app.include_router(auth_router, prefix=api_v1)
    app.include_router(profile_router, prefix=api_v1)
    app.include_router(admin_router, prefix=api_v1)

    @app.get("/health", tags=["Health"])
    async def health():
        return {
            "status": "healthy",
            "version": settings.APP_VERSION,
            "environment": settings.ENVIRONMENT.value,
        }

    @app.get("/ready", tags=["Health"])
    async def readiness():
        from fastapi.responses import JSONResponse
        try:
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            return {"status": "ready"}
        except Exception:
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready"},
            )

    return app


app = create_app()