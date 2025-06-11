"""Email service for sending OTP codes."""

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from openhands.core.logger import openhands_logger as logger


class EmailService:
    """Service for sending emails."""

    def __init__(self):
        self.smtp_host = os.environ.get('SMTP_HOST', '')
        self.smtp_port = int(os.environ.get('SMTP_PORT', '587'))
        self.smtp_username = os.environ.get('SMTP_USERNAME', '')
        self.smtp_password = os.environ.get('SMTP_PASSWORD', '')
        self.from_email = os.environ.get('SMTP_FROM_EMAIL', 'noreply@openhands.ai')
        self.enabled = bool(
            self.smtp_host and self.smtp_username and self.smtp_password
        )

    async def send_otp_email(self, to_email: str, otp_code: str) -> bool:
        """Send OTP code via email."""
        if not self.enabled:
            logger.warning('Email service not configured. OTP will be logged instead.')
            logger.info(f'OTP for {to_email}: {otp_code}')
            return True

        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.from_email
            msg['To'] = to_email
            msg['Subject'] = 'OpenHands - Your Login Code'

            # Email body
            body = f"""
            <html>
            <body>
                <h2>OpenHands Login Code</h2>
                <p>Your login code is: <strong>{otp_code}</strong></p>
                <p>This code will expire in 10 minutes.</p>
                <p>If you didn't request this code, please ignore this email.</p>
                <br>
                <p>Best regards,<br>The OpenHands Team</p>
            </body>
            </html>
            """

            msg.attach(MIMEText(body, 'html'))

            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)

            logger.info(f'OTP email sent successfully to {to_email}')
            return True

        except Exception as e:
            logger.error(f'Failed to send OTP email to {to_email}: {e}')
            return False

    async def send_welcome_email(self, to_email: str, username: str) -> bool:
        """Send welcome email to new user."""
        if not self.enabled:
            logger.info(f'Welcome email would be sent to {to_email}')
            return True

        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.from_email
            msg['To'] = to_email
            msg['Subject'] = 'Welcome to OpenHands!'

            # Email body
            body = f"""
            <html>
            <body>
                <h2>Welcome to OpenHands, {username}!</h2>
                <p>Your account has been successfully created.</p>
                <p>You can now start using OpenHands to build amazing things with AI assistance.</p>
                <br>
                <p>Get started:</p>
                <ul>
                    <li>Connect your GitHub account for repository access</li>
                    <li>Configure your preferred LLM settings</li>
                    <li>Start your first conversation</li>
                </ul>
                <br>
                <p>Best regards,<br>The OpenHands Team</p>
            </body>
            </html>
            """

            msg.attach(MIMEText(body, 'html'))

            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)

            logger.info(f'Welcome email sent successfully to {to_email}')
            return True

        except Exception as e:
            logger.error(f'Failed to send welcome email to {to_email}: {e}')
            return False


# Global email service instance
email_service = EmailService()
