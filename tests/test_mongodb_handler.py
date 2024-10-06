import unittest
from unittest.mock import patch, MagicMock
from common.mongodb_handler import get_mongodb_client
import os


class TestMongoDBHandler(unittest.TestCase):

    @patch("common.mongodb_handler.AsyncIOMotorClient")
    @patch("os.getenv")
    def test_get_mongodb_client_success(self, mock_getenv, mock_motor_client):
        # Arrange
        mock_getenv.return_value = "mongodb://mock_mongodb_uri"
        mock_motor_client.return_value = MagicMock()

        # Act
        client = get_mongodb_client()

        # Assert
        mock_getenv.assert_called_once_with("MONGODB_URI")
        mock_motor_client.assert_called_once_with("mongodb://mock_mongodb_uri")
        self.assertIsNotNone(client)

    @patch("os.getenv")
    def test_get_mongodb_client_missing_env(self, mock_getenv):
        # Arrange
        mock_getenv.return_value = None

        # Act & Assert
        with self.assertRaises(ValueError) as exc:
            get_mongodb_client()

        mock_getenv.assert_called_once_with("MONGODB_URI")
        self.assertEqual(
            str(exc.exception),
            "MONGODB_URI not set in environment variables or is empty!",
        )

    @patch("common.mongodb_handler.AsyncIOMotorClient")
    @patch("os.getenv")
    def test_get_mongodb_client_connection_failure(
        self, mock_getenv, mock_motor_client
    ):
        # Arrange
        mock_getenv.return_value = "mongodb://mock_mongodb_uri"
        mock_motor_client.side_effect = Exception("Connection failed")

        # Act & Assert
        with self.assertRaises(Exception) as exc:
            get_mongodb_client()

        mock_getenv.assert_called_once_with("MONGODB_URI")
        mock_motor_client.assert_called_once_with("mongodb://mock_mongodb_uri")
        self.assertEqual(str(exc.exception), "Connection failed")


if __name__ == "__main__":
    unittest.main()
