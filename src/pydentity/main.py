import uvicorn

from pydentity.infrastructure.settings import Settings
from pydentity.infrastructure.web.app import create_app


def main() -> None:
    settings = Settings()
    application = create_app(settings)
    uvicorn.run(
        application,
        host=settings.app_host,
        port=settings.app_port,
    )


if __name__ == "__main__":
    main()
