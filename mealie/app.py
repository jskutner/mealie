import re
import warnings

# pyrdfa3 is no longer being updated and has docstrings that emit syntax warnings
warnings.filterwarnings(
    "ignore", module=".*pyRdfa", category=SyntaxWarning, message=re.escape("invalid escape sequence '\\-'")
)

# ruff: noqa: E402
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.routing import APIRoute
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from mealie.core.config import get_app_settings
from mealie.core.root_logger import get_logger
from mealie.core.settings.static import APP_VERSION
from mealie.routes import router, spa, utility_routes
from mealie.routes.handlers import register_debug_handler
from mealie.routes.media import media_router
from mealie.services.scheduler import SchedulerRegistry, SchedulerService, tasks

settings = get_app_settings()

description = """
Mealie is a web application for managing your recipes, meal plans, and shopping lists. This is the Restful
API interactive documentation that can be used to explore the API. If you're justing getting started with
the API and want to get started quickly, you can use the
[API Usage | Mealie Docs](https://docs.mealie.io/documentation/getting-started/api-usage/)
as a reference for how to get started.


If you have any questions or comments about mealie, please use the discord server to talk to the developers or other
community members. If you'd like to file an issue, please use the
[GitHub Issue Tracker | Mealie](https://github.com/mealie-recipes/mealie/issues/new/choose)


## Helpful Links
- [Home Page](https://mealie.io)
- [Documentation](https://docs.mealie.io)
- [Discord](https://discord.gg/QuStdQGSGK)
- [Demo](https://demo.mealie.io)
"""

logger = get_logger()


@asynccontextmanager
async def lifespan_fn(_: FastAPI) -> AsyncGenerator[None, None]:
    """
    lifespan_fn controls the startup and shutdown of the FastAPI Application.
    This function is called when the FastAPI application starts and stops.

    See FastAPI documentation for more information:
      - https://fastapi.tiangolo.com/advanced/events/
    """
    logger.info("start: database initialization")
    import mealie.db.init_db as init_db

    init_db.main()
    logger.info("end: database initialization")

    await start_scheduler()

    logger.info("-----SYSTEM STARTUP-----")
    logger.info("------APP SETTINGS------")
    logger.info(
        settings.model_dump_json(
            indent=4,
            exclude={
                "SECRET",
                "SESSION_SECRET",
                "DB_URL",  # replace by DB_URL_PUBLIC for logs
                "DB_PROVIDER",
            },
        )
    )
    logger.info("------APP FEATURES------")
    logger.info("--------==SMTP==--------")
    logger.info(settings.SMTP_FEATURE)
    logger.info("--------==LDAP==--------")
    logger.info(settings.LDAP_FEATURE)
    logger.info("--------==OIDC==--------")
    logger.info(settings.OIDC_FEATURE)
    logger.info("-------==OPENAI==-------")
    logger.info(settings.OPENAI_FEATURE)
    logger.info("------------------------")

    yield

    logger.info("-----SYSTEM SHUTDOWN----- \n")


app = FastAPI(
    title="Mealie",
    description=description,
    version=APP_VERSION,
    docs_url=settings.DOCS_URL,
    redoc_url=settings.REDOC_URL,
    lifespan=lifespan_fn,
)

app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(SessionMiddleware, secret_key=settings.SESSION_SECRET)

if not settings.PRODUCTION:
    allowed_origins = ["http://localhost:3000"]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

register_debug_handler(app)


async def start_scheduler():
    SchedulerRegistry.register_daily(
        tasks.purge_expired_tokens,
        tasks.purge_group_registration,
        tasks.purge_password_reset_tokens,
        tasks.purge_group_data_exports,
        tasks.create_mealplan_timeline_events,
        tasks.delete_old_checked_list_items,
    )

    SchedulerRegistry.register_minutely(
        tasks.post_group_webhooks,
    )

    SchedulerRegistry.register_hourly(
        tasks.locked_user_reset,
    )

    SchedulerRegistry.print_jobs()

    await SchedulerService.start()


def api_routers():
    app.include_router(router)
    app.include_router(media_router)
    app.include_router(utility_routes.router)

    if settings.PRODUCTION and not settings.TESTING:
        spa.mount_spa(app)


api_routers()

# fix routes that would get their tags duplicated by use of @controller,
# leading to duplicate definitions in the openapi spec
for route in app.routes:
    if isinstance(route, APIRoute):
        route.tags = list(set(route.tags))


class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip CSRF checks in development to ease local workflows
        if not settings.PRODUCTION:
            return await call_next(request)

        # Only enforce on state-changing methods where cookie auth might be used
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            # If auth cookie is present, require Origin/Referer to match BASE_URL exactly (scheme+host+port)
            if "mealie.access_token" in request.cookies:
                origin = request.headers.get("origin") or ""
                referer = request.headers.get("referer") or ""

                try:
                    from urllib.parse import urlparse
                    allowed_parts = urlparse(settings.BASE_URL)
                    allowed = (allowed_parts.scheme, allowed_parts.hostname, allowed_parts.port)

                    def is_allowed(url: str) -> bool:
                        if not url:
                            return False
                        parts = urlparse(url)
                        host_port = parts.port
                        # Infer default port if missing
                        if host_port is None:
                            host_port = 443 if parts.scheme == "https" else 80
                        return (parts.scheme, parts.hostname, host_port) == (
                            allowed[0], allowed[1], allowed[2] or (443 if allowed_parts.scheme == "https" else 80)
                        )

                    if not (is_allowed(origin) or is_allowed(referer)):
                        from fastapi import status as _status
                        from fastapi.responses import JSONResponse
                        return JSONResponse(status_code=_status.HTTP_403_FORBIDDEN, content={"detail": "CSRF check failed"})
                except Exception:
                    from fastapi import status as _status
                    from fastapi.responses import JSONResponse
                    return JSONResponse(status_code=_status.HTTP_403_FORBIDDEN, content={"detail": "CSRF check failed"})

        return await call_next(request)


app.add_middleware(CSRFMiddleware)


def main():
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=settings.API_PORT,
        reload=True,
        reload_dirs=["mealie"],
        reload_delay=2,
        log_level="info",
        use_colors=True,
        log_config=None,
        workers=1,
        forwarded_allow_ips=settings.HOST_IP,
    )


if __name__ == "__main__":
    main()
