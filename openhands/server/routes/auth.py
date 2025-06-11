"""Authentication routes for multi-user support."""

import os
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr

from openhands.core.logger import openhands_logger as logger
from openhands.server.services.email_service import email_service
from openhands.server.user_auth.multi_user_auth import MultiUserAuth, UserSession
from openhands.server.user_auth.user_auth import get_user_auth
from openhands.storage.data_models.user_secrets import UserSecrets

router = APIRouter(prefix='/api/auth', tags=['authentication'])


class OTPRequest(BaseModel):
    """Request model for OTP generation."""

    email: EmailStr


class OTPVerification(BaseModel):
    """Request model for OTP verification."""

    email: EmailStr
    code: str


class GitHubAuthResponse(BaseModel):
    """Response model for GitHub auth URL."""

    auth_url: str
    state: str


class AuthStatus(BaseModel):
    """Response model for authentication status."""

    authenticated: bool
    user_id: str | None = None
    email: str | None = None
    github_username: str | None = None


@router.get('/status', response_model=AuthStatus)
async def get_auth_status(user_auth: MultiUserAuth = Depends(get_user_auth)):
    """Get current authentication status."""
    session = await user_auth.get_current_session()

    if session:
        return AuthStatus(
            authenticated=True,
            user_id=session.user_id,
            email=session.email,
            github_username=session.github_username,
        )
    else:
        return AuthStatus(authenticated=False)


@router.post('/otp/generate')
async def generate_otp(request: OTPRequest):
    """Generate and send OTP code to email."""
    try:
        # Generate OTP
        otp_code = MultiUserAuth.generate_otp()

        # Store OTP
        MultiUserAuth.store_otp(request.email, otp_code)

        # Send OTP via email
        email_sent = await email_service.send_otp_email(request.email, otp_code)
        if not email_sent:
            logger.warning(
                f'Failed to send OTP email to {request.email}, but OTP is stored'
            )

        return {'message': 'OTP sent successfully', 'email': request.email}

    except Exception as e:
        logger.error(f'Failed to generate OTP: {e}')
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Failed to generate OTP',
        )


@router.post('/otp/verify')
async def verify_otp(request: OTPVerification, response: Response):
    """Verify OTP and create session if valid."""
    try:
        # Verify OTP
        if not MultiUserAuth.verify_otp(request.email, request.code):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid or expired OTP'
            )

        # Create user session
        user_data = {
            'user_id': f'email_{request.email}',  # Simple user ID based on email
            'email': request.email,
            'github_id': '',  # Will be filled when GitHub is connected
            'github_username': '',
        }

        session_token = MultiUserAuth.create_user_session(user_data)

        # Set secure cookie
        response.set_cookie(
            key='openhands_session',
            value=session_token,
            httponly=True,
            secure=True,  # Use HTTPS in production
            samesite='lax',
            max_age=7 * 24 * 60 * 60,  # 7 days
        )

        return {
            'message': 'Authentication successful',
            'user_id': user_data['user_id'],
            'email': user_data['email'],
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f'Failed to verify OTP: {e}')
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Failed to verify OTP',
        )


@router.get('/github/url', response_model=GitHubAuthResponse)
async def get_github_auth_url(request: Request):
    """Get GitHub OAuth authorization URL."""
    try:
        client_id = os.environ.get('GITHUB_APP_CLIENT_ID')
        if not client_id:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail='GitHub OAuth not configured',
            )

        # Generate state parameter for CSRF protection
        state = secrets.token_urlsafe(32)

        # Store state in session (in production, use Redis or database)
        # For now, we'll use a simple in-memory store
        if not hasattr(get_github_auth_url, '_states'):
            get_github_auth_url._states = {}
        get_github_auth_url._states[state] = True

        # Build GitHub OAuth URL
        params = {
            'client_id': client_id,
            'redirect_uri': f'{request.base_url}api/auth/github/callback',
            'scope': 'user:email',
            'state': state,
        }

        auth_url = f'https://github.com/login/oauth/authorize?{urlencode(params)}'

        return GitHubAuthResponse(auth_url=auth_url, state=state)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f'Failed to generate GitHub auth URL: {e}')
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Failed to generate GitHub auth URL',
        )


@router.get('/github/callback')
async def github_callback(
    request: Request,
    response: Response,
    code: str,
    state: str,
    user_auth: MultiUserAuth = Depends(get_user_auth),
):
    """Handle GitHub OAuth callback."""
    try:
        # Verify state parameter
        if (
            not hasattr(get_github_auth_url, '_states')
            or state not in get_github_auth_url._states
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='Invalid state parameter',
            )

        # Remove used state
        del get_github_auth_url._states[state]

        client_id = os.environ.get('GITHUB_APP_CLIENT_ID')
        client_secret = os.environ.get('GITHUB_APP_CLIENT_SECRET')

        if not client_id or not client_secret:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail='GitHub OAuth not configured',
            )

        # Exchange code for access token
        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                'https://github.com/login/oauth/access_token',
                data={
                    'client_id': client_id,
                    'client_secret': client_secret,
                    'code': code,
                },
                headers={'Accept': 'application/json'},
            )

            if token_response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail='Failed to exchange code for token',
                )

            token_data = token_response.json()
            access_token = token_data.get('access_token')

            if not access_token:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail='No access token received',
                )

            # Get user info from GitHub
            user_response = await client.get(
                'https://api.github.com/user',
                headers={'Authorization': f'Bearer {access_token}'},
            )

            if user_response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail='Failed to get user info from GitHub',
                )

            user_data = user_response.json()

            # Get user email
            email_response = await client.get(
                'https://api.github.com/user/emails',
                headers={'Authorization': f'Bearer {access_token}'},
            )

            primary_email = None
            if email_response.status_code == 200:
                emails = email_response.json()
                for email in emails:
                    if email.get('primary'):
                        primary_email = email.get('email')
                        break

            if not primary_email:
                primary_email = user_data.get(
                    'email', f'{user_data["login"]}@github.local'
                )

        # Check if user is already authenticated via OTP
        current_session = await user_auth.get_current_session()

        if current_session:
            # Update existing session with GitHub info
            user_id = current_session.user_id
            email = current_session.email
        else:
            # Create new session
            user_id = f'github_{user_data["id"]}'
            email = primary_email

        # Create/update user session
        session_user_data = {
            'user_id': user_id,
            'email': email,
            'github_id': str(user_data['id']),
            'github_username': user_data['login'],
            'access_token': access_token,
        }

        session_token = MultiUserAuth.create_user_session(session_user_data)

        # Store GitHub access token in user secrets
        # Create a temporary auth instance for the new user
        temp_auth = MultiUserAuth(request)
        temp_auth._current_session = UserSession(
            user_id=user_id,
            email=email,
            github_id=str(user_data['id']),
            github_username=user_data['login'],
            access_token=access_token,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
            session_token=session_token,
        )

        secrets_store = await temp_auth.get_secrets_store()
        user_secrets = await secrets_store.load() or UserSecrets()

        # Create a new provider tokens dict with the GitHub token
        from types import MappingProxyType

        from openhands.integrations.provider import ProviderToken
        from openhands.integrations.service_types import ProviderType

        provider_tokens_dict = (
            dict(user_secrets.provider_tokens) if user_secrets.provider_tokens else {}
        )
        provider_tokens_dict[ProviderType.GITHUB] = ProviderToken.from_value(
            access_token
        )

        # Create new UserSecrets with updated provider tokens
        user_secrets = UserSecrets(
            provider_tokens=MappingProxyType(provider_tokens_dict),
            custom_secrets=user_secrets.custom_secrets,
        )
        await secrets_store.store(user_secrets)

        # Set secure cookie
        response.set_cookie(
            key='openhands_session',
            value=session_token,
            httponly=True,
            secure=True,  # Use HTTPS in production
            samesite='lax',
            max_age=7 * 24 * 60 * 60,  # 7 days
        )

        # Redirect to frontend
        from fastapi.responses import RedirectResponse

        return RedirectResponse(url='/', status_code=302)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f'GitHub callback failed: {e}')
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='GitHub authentication failed',
        )


@router.post('/logout')
async def logout(response: Response, user_auth: MultiUserAuth = Depends(get_user_auth)):
    """Logout current user."""
    try:
        session = await user_auth.get_current_session()
        if session:
            MultiUserAuth.invalidate_session(session.session_token)

        # Clear cookie
        response.delete_cookie(
            key='openhands_session', httponly=True, secure=True, samesite='lax'
        )

        return {'message': 'Logged out successfully'}

    except Exception as e:
        logger.error(f'Logout failed: {e}')
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Logout failed'
        )


@router.delete('/sessions/cleanup')
async def cleanup_sessions():
    """Clean up expired sessions and OTP codes (admin endpoint)."""
    try:
        MultiUserAuth.cleanup_expired_sessions()
        return {'message': 'Cleanup completed'}

    except Exception as e:
        logger.error(f'Session cleanup failed: {e}')
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Session cleanup failed',
        )
