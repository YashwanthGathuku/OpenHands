"""Tests for multi-user authentication system."""

from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

import pytest

from openhands.server.user_auth.multi_user_auth import MultiUserAuth, UserSession


class TestMultiUserAuth:
    """Test cases for MultiUserAuth class."""

    def test_user_session_creation(self):
        """Test UserSession dataclass creation."""
        session = UserSession(
            user_id='test_user',
            email='test@example.com',
            github_id='123',
            github_username='testuser',
            access_token='token123',
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
            session_token='session123',
        )

        assert session.user_id == 'test_user'
        assert session.email == 'test@example.com'
        assert session.github_id == '123'
        assert session.github_username == 'testuser'

    def test_create_user_session(self):
        """Test JWT session token creation."""
        session_data = {
            'user_id': 'test_user',
            'email': 'test@example.com',
            'github_id': '123',
            'github_username': 'testuser',
            'access_token': 'token123',
            'created_at': datetime.now(timezone.utc).isoformat(),
            'expires_at': (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
        }

        with patch.dict('os.environ', {'OPENHANDS_JWT_SECRET': 'test_secret'}):
            token = MultiUserAuth.create_user_session(session_data)
            assert isinstance(token, str)
            assert len(token) > 0

    def test_verify_user_session(self):
        """Test JWT session token verification."""
        session_data = {
            'user_id': 'test_user',
            'email': 'test@example.com',
            'github_id': '123',
            'github_username': 'testuser',
            'access_token': 'token123',
            'created_at': datetime.now(timezone.utc).isoformat(),
            'expires_at': (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
        }

        with patch.dict('os.environ', {'OPENHANDS_JWT_SECRET': 'test_secret'}):
            token = MultiUserAuth.create_user_session(session_data)
            verified_data = MultiUserAuth.verify_session_token(token)

            assert verified_data['user_id'] == 'test_user'
            assert verified_data['email'] == 'test@example.com'

    def test_generate_otp(self):
        """Test OTP generation."""
        otp = MultiUserAuth.generate_otp()
        assert isinstance(otp, str)
        assert len(otp) == 6
        assert otp.isdigit()

    def test_verify_otp_valid(self):
        """Test OTP verification with valid code."""
        email = 'test@example.com'
        otp = '123456'

        # Create an instance to access the OTP storage
        mock_request = Mock()
        auth = MultiUserAuth(mock_request)

        # Store OTP using the store_otp method
        auth.store_otp(email, otp)

        # Verify OTP
        is_valid = auth.verify_otp(email, otp)
        assert is_valid is True

    def test_verify_otp_invalid(self):
        """Test OTP verification with invalid code."""
        email = 'test@example.com'

        # Create an instance to access the OTP storage
        mock_request = Mock()
        auth = MultiUserAuth(mock_request)

        # Store OTP
        auth.store_otp(email, '123456')

        # Try to verify with wrong OTP
        is_valid = auth.verify_otp(email, '654321')
        assert is_valid is False

    def test_verify_otp_expired(self):
        """Test OTP verification with expired code."""
        email = 'test@example.com'
        otp = '123456'

        # Create an instance to access the OTP storage
        mock_request = Mock()
        auth = MultiUserAuth(mock_request)

        # Manually create an expired OTP
        from openhands.server.user_auth.multi_user_auth import OTPCode

        expired_otp = OTPCode(
            code=otp,
            email=email,
            created_at=datetime.now(timezone.utc) - timedelta(minutes=10),
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        )
        auth._otp_codes[email] = expired_otp

        # Verify expired OTP
        is_valid = auth.verify_otp(email, otp)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_get_user_id(self):
        """Test getting user ID from session."""
        mock_request = Mock()
        mock_request.cookies = {'openhands_session': 'valid_token'}

        auth = MultiUserAuth(mock_request)

        # Mock session data
        session = UserSession(
            user_id='test_user',
            email='test@example.com',
            github_id='123',
            github_username='testuser',
            access_token='token123',
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
            session_token='valid_token',
        )
        auth._current_session = session

        user_id = await auth.get_user_id()
        assert user_id == 'test_user'

    @pytest.mark.asyncio
    async def test_get_user_id_no_session(self):
        """Test getting user ID when no session exists."""
        mock_request = Mock()
        mock_request.cookies = {}
        mock_request.headers = {}

        auth = MultiUserAuth(mock_request)

        user_id = await auth.get_user_id()
        assert user_id is None

    @pytest.mark.asyncio
    async def test_get_current_session(self):
        """Test getting current session."""
        # Create a valid session token first
        session_data = {
            'user_id': 'test_user',
            'email': 'test@example.com',
            'github_id': '123',
            'github_username': 'testuser',
            'access_token': 'token123',
            'created_at': datetime.now(timezone.utc).isoformat(),
            'expires_at': (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
        }

        with patch.dict('os.environ', {'OPENHANDS_JWT_SECRET': 'test_secret'}):
            token = MultiUserAuth.create_user_session(session_data)

            mock_request = Mock()
            mock_request.cookies = {'openhands_session': token}
            mock_request.headers = {}

            auth = MultiUserAuth(mock_request)

            current_session = await auth.get_current_session()
            assert current_session is not None
            assert current_session.user_id == 'test_user'
