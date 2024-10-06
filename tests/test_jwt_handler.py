import unittest
from unittest.mock import patch, AsyncMock
from finappsvc.common.jwt_handler import create_access_token, get_current_user
from datetime import timedelta, datetime, timezone
from fastapi import HTTPException
from jose import JWTError
import jwt


class TestJWTHandler(unittest.TestCase):

    @patch("finappsvc.common.jwt_handler.JWT_SECRET_KEY", "test_secret_key")
    @patch("finappsvc.common.jwt_handler.jwt.encode")
    @patch("finappsvc.common.jwt_handler.datetime")
    def test_create_access_token(self, mock_datetime, mock_jwt_encode):
        # Arrange
        mock_jwt_encode.return_value = "mock_token"
        mock_datetime.now.return_value = datetime(
            2024, 10, 6, 12, 30, 0, tzinfo=timezone.utc
        )
        data = {"sub": "test_user"}
        expires_delta = timedelta(minutes=5)

        # Act
        token = create_access_token(data, expires_delta)

        # Assert
        self.assertEqual(token, "mock_token")
        mock_jwt_encode.assert_called_once_with(
            {"sub": "test_user", "exp": mock_datetime.now() + expires_delta},
            "test_secret_key",
            algorithm="HS256",
        )

    @patch("finappsvc.common.jwt_handler.JWT_SECRET_KEY", "test_secret_key")
    @patch("finappsvc.common.jwt_handler.jwt.decode")
    @patch("finappsvc.common.jwt_handler.oauth2_scheme", return_value="mock_token")
    def test_get_current_user_valid_token(self, mock_oauth2_scheme, mock_jwt_decode):
        # Arrange
        mock_jwt_decode.return_value = {"sub": "test_user"}

        # Act
        username = self.run_async(get_current_user(token="mock_token"))

        # Assert
        self.assertEqual(username, "test_user")
        mock_jwt_decode.assert_called_once_with(
            "mock_token", "test_secret_key", algorithms=["HS256"]
        )

    @patch("finappsvc.common.jwt_handler.JWT_SECRET_KEY", "test_secret_key")
    @patch("finappsvc.common.jwt_handler.jwt.decode")
    @patch("finappsvc.common.jwt_handler.oauth2_scheme", return_value="mock_token")
    def test_get_current_user_invalid_token(self, mock_oauth2_scheme, mock_jwt_decode):
        # Arrange
        mock_jwt_decode.side_effect = JWTError()

        # Act / Assert
        with self.assertRaises(HTTPException) as context:
            self.run_async(get_current_user(token="mock_token"))

        self.assertEqual(context.exception.status_code, 401)
        self.assertEqual(context.exception.detail, "Could not validate credentials")

    @patch("finappsvc.common.jwt_handler.JWT_SECRET_KEY", "test_secret_key")
    @patch("finappsvc.common.jwt_handler.jwt.decode")
    @patch("finappsvc.common.jwt_handler.oauth2_scheme", return_value="mock_token")
    def test_get_current_user_missing_username(
        self, mock_oauth2_scheme, mock_jwt_decode
    ):
        # Arrange
        mock_jwt_decode.return_value = {"sub": None}

        # Act / Assert
        with self.assertRaises(HTTPException) as context:
            self.run_async(get_current_user(token="mock_token"))

        self.assertEqual(context.exception.status_code, 401)
        self.assertEqual(context.exception.detail, "Could not validate credentials")

    def run_async(self, coro):
        """Helper function to run asynchronous code in tests."""
        try:
            return coro.__await__().__next__()
        except StopIteration as e:
            return e.value


if __name__ == "__main__":
    unittest.main()
