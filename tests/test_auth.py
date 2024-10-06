import unittest
from unittest.mock import patch, MagicMock
from fastapi import HTTPException
from common.auth import authenticate_message
from common.jwt_handler import JWTError


class TestAuth(unittest.TestCase):

    @patch("common.auth.jwt.decode")
    def test_authenticate_message_success(self, mock_jwt_decode):
        # Arrange
        mock_jwt_decode.return_value = {"sub": "test_user"}
        token = "mock_valid_token"

        # Act
        username = authenticate_message(token)

        # Assert
        mock_jwt_decode.assert_called_once_with(
            token, "your_secret_key", algorithms=["HS256"]
        )
        self.assertEqual(username, "test_user")

    @patch("common.auth.jwt.decode")
    def test_authenticate_message_invalid_payload(self, mock_jwt_decode):
        # Arrange
        mock_jwt_decode.return_value = {"sub": None}
        token = "mock_invalid_token"

        # Act & Assert
        with self.assertRaises(HTTPException) as exc:
            authenticate_message(token)

        mock_jwt_decode.assert_called_once_with(
            token, "your_secret_key", algorithms=["HS256"]
        )
        self.assertEqual(exc.exception.status_code, 401)
        self.assertEqual(exc.exception.detail, "Invalid token")

    @patch("common.auth.jwt.decode")
    def test_authenticate_message_jwt_error(self, mock_jwt_decode):
        # Arrange
        mock_jwt_decode.side_effect = JWTError("Invalid token")
        token = "mock_invalid_token"

        # Act & Assert
        with self.assertRaises(HTTPException) as exc:
            authenticate_message(token)

        mock_jwt_decode.assert_called_once_with(
            token, "your_secret_key", algorithms=["HS256"]
        )
        self.assertEqual(exc.exception.status_code, 401)
        self.assertEqual(exc.exception.detail, "Invalid token")


if __name__ == "__main__":
    unittest.main()
