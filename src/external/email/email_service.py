import logging
from datetime import datetime
from pathlib import Path

from fastapi_mail import ConnectionConfig, FastMail, MessageSchema, MessageType
from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.config import settings
from src.core.protocols import EmailServiceProtocol

logger = logging.getLogger(__name__)

_TEMPLATE_DIR = Path(__file__).parent / "templates"

_jinja_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(["html"]),
)

_mail_config = ConnectionConfig(
    MAIL_USERNAME=settings.MAIL_USERNAME,
    MAIL_PASSWORD=settings.MAIL_PASSWORD.get_secret_value(),
    MAIL_FROM=settings.MAIL_FROM,
    MAIL_PORT=settings.MAIL_PORT,
    MAIL_SERVER=settings.MAIL_SERVER,
    MAIL_STARTTLS=settings.MAIL_STARTTLS,
    MAIL_SSL_TLS=settings.MAIL_SSL_TLS,
    USE_CREDENTIALS=True,
)


class EmailService(EmailServiceProtocol):
    def __init__(self):
        self._mailer = FastMail(_mail_config)

    async def send_confirmation_email(
        self, email: str, username: str, token: str,
    ) -> None:
        confirmation_link = (
            f"{settings.BASE_URL}/api/v1/auth/email-confirm?token={token}"
        )

        html = self._render_template(
            "confirm_email.html",
            username=username,
            confirmation_link=confirmation_link,
            expires_in_minutes=(
                settings.EMAIL_CONFIRM_TOKEN_EXPIRE_SECONDS // 60
            ),
        )

        await self._send(
            to=email,
            subject=f"Confirm your email — {settings.APP_NAME}",
            html=html,
        )

        logger.info(
            {
                "event": "confirmation_email_sent",
            }
        )

    async def send_password_reset_email(
        self, email: str, username: str, token: str,
    ) -> None:
        reset_link = (
            f"{settings.BASE_URL}/api/v1/auth/password-reset/"
            f"confirm?token={token}"
        )

        html = self._render_template(
            "reset_password.html",
            username=username,
            reset_link=reset_link,
            expires_in_minutes=(
                settings.PASSWORD_RESET_TOKEN_EXPIRE_SECONDS // 60
            ),
        )

        await self._send(
            to=email,
            subject=f"Password Reset — {settings.APP_NAME}",
            html=html,
        )

        logger.info(
            {
                "event": "password_reset_email_sent",
            }
        )

    def _render_template(self, template_name: str, **kwargs) -> str:
        template = _jinja_env.get_template(template_name)
        return template.render(
            app_name=settings.APP_NAME,
            year=datetime.now().year,
            subject=kwargs.get("subject", settings.APP_NAME),
            **kwargs,
        )

    async def _send(self, to: str, subject: str, html: str) -> None:
        message = MessageSchema(
            subject=subject,
            recipients=[to],
            body=html,
            subtype=MessageType.html,
        )

        try:
            await self._mailer.send_message(message)
        except Exception as e:
            logger.error(
                {
                    "event": "email_send_failed",
                    "error": type(e).__name__,
                    "message": str(e),
                }
            )