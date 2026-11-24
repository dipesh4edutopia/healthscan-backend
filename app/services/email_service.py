"""
Transactional Email Delivery Service (Forgot Password OTPs & Verification)
Supports:
  - Resend HTTPS API (recommended on Render: set RESEND_API_KEY)
  - SMTP STARTTLS (set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS)
  - Console logging fallback in development / testing
"""

import logging
import smtplib
from email.message import EmailMessage
import requests

from app.config import Config

logger = logging.getLogger(__name__)


class EmailDeliveryError(Exception):
    """Raised when an email provider fails to send a message."""
    pass


def _resolve_provider() -> str:
    explicit = (Config.EMAIL_PROVIDER or "").strip().lower()
    if explicit in ("resend", "smtp", "console"):
        return explicit
    if Config.RESEND_API_KEY:
        return "resend"
    if Config.SMTP_HOST:
        return "smtp"
    return "console"


def send_email(to_email: str, subject: str, text_body: str, html_body: str = "") -> str:
    """
    Sends an email using the configured provider.
    Returns the provider name used ('resend' | 'smtp' | 'console').
    """
    provider = _resolve_provider()

    if provider == "resend":
        if not Config.RESEND_API_KEY:
            raise EmailDeliveryError("RESEND_API_KEY is not configured.")
        resp = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {Config.RESEND_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "from": Config.EMAIL_FROM,
                "to": [to_email],
                "subject": subject,
                "text": text_body,
                "html": html_body or text_body.replace("\n", "<br/>"),
            },
            timeout=15,
        )
        if not resp.ok:
            logger.error("Resend API error %s: %s", resp.status_code, resp.text)
            raise EmailDeliveryError(f"Email delivery failed ({resp.status_code}).")
        return "resend"

    if provider == "smtp":
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = Config.EMAIL_FROM
        msg["To"] = to_email
        msg.set_content(text_body)
        if html_body:
            msg.add_alternative(html_body, subtype="html")

        try:
            with smtplib.SMTP(Config.SMTP_HOST, Config.SMTP_PORT, timeout=15) as server:
                server.starttls()
                if Config.SMTP_USER and Config.SMTP_PASS:
                    server.login(Config.SMTP_USER, Config.SMTP_PASS)
                server.send_message(msg)
        except Exception as exc:
            logger.error("SMTP delivery error: %s", exc)
            raise EmailDeliveryError(f"SMTP delivery failed: {exc}") from exc
        return "smtp"

    # Console fallback (development / testing)
    logger.info("[DEV EMAIL -> %s] %s\n%s", to_email, subject, text_body)
    return "console"


def send_password_reset_otp(to_email: str, otp_code: str, app_name: str = "Our App") -> str:
    subject = f"{otp_code} is your {app_name} password reset code"
    ttl = Config.PASSWORD_RESET_OTP_MINUTES
    text_body = (
        f"Hello,\n\n"
        f"Your password reset code for {app_name} is: {otp_code}\n\n"
        f"This code expires in {ttl} minutes. If you didn't request this, you can safely ignore this email."
    )
    html_body = (
        f"<p>Hello,</p>"
        f"<p>Your password reset code for <strong>{app_name}</strong> is:</p>"
        f"<h2 style='letter-spacing:4px;font-family:monospace;'>{otp_code}</h2>"
        f"<p>This code expires in {ttl} minutes. If you didn't request this, you can safely ignore this email.</p>"
    )
    return send_email(to_email, subject, text_body, html_body)
