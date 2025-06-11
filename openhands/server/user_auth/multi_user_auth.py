"""Multi-user authentication with GitHub OAuth and OTP support."""

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from fastapi import Request
from pydantic import SecretStr

from openhands.core.logger import openhands_logger as logger
from openhands.integrations.provider import PROVIDER_TOKEN_TYPE
from openhands.server import shared
from openhands.server.settings import Settings
from openhands.server.user_auth.user_auth import AuthType, UserAuth
from openhands.storage.data_models.user_secrets import UserSecrets
from openhands.storage.secrets.secrets_store import SecretsStore
from openhands.storage.settings.settings_store import SettingsStore


@dataclass
class UserSession:
    """User session data."""

    user_id: str
    email: str
    github_id: str
    github_username: str
    access_token: str
    created_at: datetime
    expires_at: datetime
    session_token: str


@dataclass
class OTPCode:
    """OTP code data."""

    code: str
    email: str
    created_at: datetime
    expires_at: datetime
    attempts: int = 0


class MultiUserAuth(UserAuth):
    """Multi-user authentication with GitHub OAuth and OTP support."""

    # Class-level storage for sessions and OTP codes
    # In production, these should be stored in Redis or a database
    _sessions: dict[str, UserSession] = {}
    _otp_codes: dict[str, OTPCode] = {}

    def __init__(self, request: Request):
        self.request = request
        self._settings: Settings | None = None
        self._settings_store: SettingsStore | None = None
        self._secrets_store: SecretsStore | None = None
        self._user_secrets: UserSecrets | None = None
        self._current_session: UserSession | None = None

    @classmethod
    def get_jwt_secret(cls) -> str:
        """Get JWT secret from environment or generate one."""
        import os

        secret = os.environ.get('OPENHANDS_JWT_SECRET')
        if not secret:
            # In production, this should be set as an environment variable
            secret = 'openhands-default-jwt-secret-change-in-production'
            logger.warning(
                'Using default JWT secret. Set OPENHANDS_JWT_SECRET environment variable in production.'
            )
        return secret

    @classmethod
    def generate_otp(cls) -> str:
        """Generate a 6-digit OTP code."""
        return f'{secrets.randbelow(1000000):06d}'

    @classmethod
    def create_session_token(cls, user_data: dict[str, Any]) -> str:
        """Create a JWT session token."""
        payload = {
            'user_id': user_data['user_id'],
            'email': user_data['email'],
            'github_id': user_data['github_id'],
            'github_username': user_data['github_username'],
            'exp': datetime.now(timezone.utc) + timedelta(days=7),  # 7 days expiry
            'iat': datetime.now(timezone.utc),
        }
        return jwt.encode(payload, cls.get_jwt_secret(), algorithm='HS256')

    @classmethod
    def verify_session_token(cls, token: str) -> dict[str, Any] | None:
        """Verify and decode a JWT session token."""
        try:
            payload = jwt.decode(token, cls.get_jwt_secret(), algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            logger.debug('Session token expired')
            return None
        except jwt.InvalidTokenError:
            logger.debug('Invalid session token')
            return None

    def get_session_token_from_request(self) -> str | None:
        """Extract session token from request."""
        # Try Authorization header first
        auth_header = self.request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            return auth_header[7:]

        # Try cookie
        return self.request.cookies.get('openhands_session')

    async def get_current_session(self) -> UserSession | None:
        """Get current user session."""
        if self._current_session:
            return self._current_session

        token = self.get_session_token_from_request()
        if not token:
            return None

        payload = self.verify_session_token(token)
        if not payload:
            return None

        # Create session object from token payload
        self._current_session = UserSession(
            user_id=payload['user_id'],
            email=payload['email'],
            github_id=payload['github_id'],
            github_username=payload['github_username'],
            access_token='',  # We don't store this in JWT for security
            created_at=datetime.fromtimestamp(payload['iat'], timezone.utc),
            expires_at=datetime.fromtimestamp(payload['exp'], timezone.utc),
            session_token=token,
        )

        return self._current_session

    async def get_user_id(self) -> str | None:
        """Get the unique identifier for the current user."""
        session = await self.get_current_session()
        return session.user_id if session else None

    async def get_user_email(self) -> str | None:
        """Get the email for the current user."""
        session = await self.get_current_session()
        return session.email if session else None

    async def get_access_token(self) -> SecretStr | None:
        """Get the access token for the current user."""
        # For security, we don't store GitHub access tokens in JWT
        # Instead, we store them in the user's secrets
        from openhands.integrations.service_types import ProviderType

        user_secrets = await self.get_user_secrets()
        if user_secrets and user_secrets.provider_tokens:
            github_token = user_secrets.provider_tokens.get(ProviderType.GITHUB)
            if github_token and github_token.token:
                return github_token.token
        return None

    async def get_provider_tokens(self) -> PROVIDER_TOKEN_TYPE | None:
        """Get the provider tokens for the current user."""
        user_secrets = await self.get_user_secrets()
        if user_secrets is None:
            return None
        return user_secrets.provider_tokens

    async def get_user_settings_store(self) -> SettingsStore:
        """Get the settings store for the current user."""
        if self._settings_store:
            return self._settings_store

        user_id = await self.get_user_id()
        settings_store = await shared.SettingsStoreImpl.get_instance(
            shared.config, user_id
        )
        if settings_store is None:
            raise ValueError('Failed to get settings store instance')
        self._settings_store = settings_store
        return settings_store

    async def get_secrets_store(self) -> SecretsStore:
        """Get secrets store for the current user."""
        if self._secrets_store:
            return self._secrets_store

        user_id = await self.get_user_id()
        secrets_store = await shared.SecretsStoreImpl.get_instance(
            shared.config, user_id
        )
        if secrets_store is None:
            raise ValueError('Failed to get secrets store instance')
        self._secrets_store = secrets_store
        return secrets_store

    async def get_user_secrets(self) -> UserSecrets | None:
        """Get the user's secrets."""
        if self._user_secrets:
            return self._user_secrets

        secrets_store = await self.get_secrets_store()
        user_secrets = await secrets_store.load()
        self._user_secrets = user_secrets
        return user_secrets

    def get_auth_type(self) -> AuthType | None:
        """Get the authentication type."""
        token = self.get_session_token_from_request()
        if token:
            auth_header = self.request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                return AuthType.BEARER
            return AuthType.COOKIE
        return None

    @classmethod
    async def get_instance(cls, request: Request) -> UserAuth:
        """Get an instance of MultiUserAuth from the request."""
        return cls(request)

    # OTP Management Methods

    @classmethod
    def store_otp(cls, email: str, code: str) -> None:
        """Store OTP code for email."""
        cls._otp_codes[email] = OTPCode(
            code=code,
            email=email,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc)
            + timedelta(minutes=10),  # 10 minutes expiry
        )

    @classmethod
    def verify_otp(cls, email: str, code: str) -> bool:
        """Verify OTP code for email."""
        otp_data = cls._otp_codes.get(email)
        if not otp_data:
            return False

        # Check if expired
        if datetime.now(timezone.utc) > otp_data.expires_at:
            del cls._otp_codes[email]
            return False

        # Check attempts limit
        if otp_data.attempts >= 3:
            del cls._otp_codes[email]
            return False

        # Verify code
        if otp_data.code == code:
            del cls._otp_codes[email]
            return True
        else:
            otp_data.attempts += 1
            return False

    # Session Management Methods

    @classmethod
    def create_user_session(cls, user_data: dict[str, Any]) -> str:
        """Create a new user session and return session token."""
        session_token = cls.create_session_token(user_data)

        session = UserSession(
            user_id=user_data['user_id'],
            email=user_data['email'],
            github_id=user_data['github_id'],
            github_username=user_data['github_username'],
            access_token=user_data.get('access_token', ''),
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
            session_token=session_token,
        )

        cls._sessions[session_token] = session
        return session_token

    @classmethod
    def invalidate_session(cls, session_token: str) -> bool:
        """Invalidate a user session."""
        if session_token in cls._sessions:
            del cls._sessions[session_token]
            return True
        return False

    @classmethod
    def cleanup_expired_sessions(cls) -> None:
        """Clean up expired sessions and OTP codes."""
        now = datetime.now(timezone.utc)

        # Clean up expired sessions
        expired_sessions = [
            token
            for token, session in cls._sessions.items()
            if session.expires_at < now
        ]
        for token in expired_sessions:
            del cls._sessions[token]

        # Clean up expired OTP codes
        expired_otps = [
            email for email, otp in cls._otp_codes.items() if otp.expires_at < now
        ]
        for email in expired_otps:
            del cls._otp_codes[email]
