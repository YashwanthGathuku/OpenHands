"""Multi-user server configuration."""

import os

from openhands.server.config.server_config import ServerConfig
from openhands.server.types import AppMode


class MultiUserConfig(ServerConfig):
    """Server configuration for multi-user mode."""

    app_mode = AppMode.MULTI_USER

    # Override user auth class to use multi-user authentication
    user_auth_class: str = 'openhands.server.user_auth.multi_user_auth.MultiUserAuth'

    # GitHub OAuth configuration
    github_client_id = os.environ.get('GITHUB_APP_CLIENT_ID', '')
    github_client_secret = os.environ.get('GITHUB_APP_CLIENT_SECRET', '')

    # JWT configuration
    jwt_secret = os.environ.get('OPENHANDS_JWT_SECRET', '')

    # Email configuration (for OTP)
    smtp_host = os.environ.get('SMTP_HOST', '')
    smtp_port = int(os.environ.get('SMTP_PORT', '587'))
    smtp_username = os.environ.get('SMTP_USERNAME', '')
    smtp_password = os.environ.get('SMTP_PASSWORD', '')
    smtp_from_email = os.environ.get('SMTP_FROM_EMAIL', 'noreply@openhands.ai')

    def verify_config(self):
        """Verify multi-user configuration."""
        super().verify_config()

        if not self.github_client_id:
            raise ValueError(
                'GITHUB_APP_CLIENT_ID environment variable is required for multi-user mode'
            )

        if not self.github_client_secret:
            raise ValueError(
                'GITHUB_APP_CLIENT_SECRET environment variable is required for multi-user mode'
            )

        if not self.jwt_secret:
            raise ValueError(
                'OPENHANDS_JWT_SECRET environment variable is required for multi-user mode'
            )

    def get_config(self):
        """Get configuration for frontend."""
        config = super().get_config()
        config.update(
            {
                'APP_MODE': self.app_mode,
                'GITHUB_CLIENT_ID': self.github_client_id,
                'FEATURE_FLAGS': {
                    **config.get('FEATURE_FLAGS', {}),
                    'MULTI_USER': True,
                    'GITHUB_OAUTH': bool(self.github_client_id),
                    'OTP_AUTH': True,
                },
            }
        )
        return config
