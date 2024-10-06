import unittest
from unittest.mock import patch, AsyncMock, MagicMock
import asyncio
from finappsvc.notification_service.notificationsvc import log_event, callback
from finappsvc.common.database import connect_to_mongodb


class TestNotificationService(unittest.IsolatedAsyncioTestCase):

    @classmethod
    def setUpClass(cls):
        # Initialize MongoDB client and collection before all tests
        cls.client, cls.analytics_collection = connect_to_mongodb()

    @classmethod
    def tearDownClass(cls):
        # Close the MongoDB client after all tests are done
        cls.client.close()

    @patch(
        "finappsvc.notification_service.notificationsvc.analytics_collection",
        new_callable=lambda: TestNotificationService.analytics_collection,
    )
    @patch("finappsvc.notification_service.notificationsvc.logger")
    async def test_log_event_success(self, mock_logger, mock_analytics_collection):
        # Arrange
        mock_analytics_collection.insert_one = AsyncMock(
            return_value=MagicMock(inserted_id="12345")
        )
        username = "test_user"
        event = "test_event"

        # Act
        await log_event(username, event)

        # Assert
        mock_logger.info.assert_any_call(f"Logging event: {event} for user: {username}")
        mock_logger.info.assert_any_call(
            f"Event logged successfully for user: {username}. Inserted ID: 12345"
        )
        mock_analytics_collection.insert_one.assert_awaited_once()

    @patch("finappsvc.notification_service.notificationsvc.logger")
    async def test_log_event_failure(self, mock_logger):
        # Arrange
        with patch(
            "finappsvc.notification_service.notificationsvc.analytics_collection.insert_one",
            side_effect=Exception("DB Error"),
        ):
            username = "test_user"
            event = "test_event"

            # Act
            await log_event(username, event)

            # Assert
            mock_logger.error.assert_called_once_with(
                f"Failed to log event for {username}: DB Error"
            )

    @patch(
        "finappsvc.notification_service.notificationsvc.authenticate_message",
        return_value="test_user",
    )
    @patch("finappsvc.notification_service.notificationsvc.logger")
    async def test_callback_success(self, mock_logger, mock_authenticate_message):
        # Arrange
        ch = MagicMock()
        method = MagicMock(delivery_tag="123")
        properties = MagicMock(headers={"Authorization": "valid_token"})
        body = b"test_message"

        # Act
        await callback(ch, method, properties, body)

        # Assert
        mock_logger.info.assert_any_call("JWT Token being received : valid_token")
        mock_logger.info.assert_any_call("Message received from queue: test_message")
        mock_logger.info.assert_any_call(
            "Message from test_user processed successfully."
        )
        ch.basic_ack.assert_called_once_with(delivery_tag="123")

    @patch("finappsvc.notification_service.notificationsvc.logger")
    async def test_callback_no_headers(self, mock_logger):
        # Arrange
        ch = MagicMock()
        method = MagicMock(delivery_tag="123")
        properties = MagicMock(headers=None)
        body = b"test_message"

        # Act
        await callback(ch, method, properties, body)

        # Assert
        mock_logger.error.assert_called_once_with("No headers found in the message")
        ch.basic_nack.assert_called_once_with(delivery_tag="123", requeue=False)

    @patch("finappsvc.notification_service.notificationsvc.logger")
    async def test_callback_missing_token(self, mock_logger):
        # Arrange
        ch = MagicMock()
        method = MagicMock(delivery_tag="123")
        properties = MagicMock(headers={})
        body = b"test_message"

        # Act
        await callback(ch, method, properties, body)

        # Assert
        mock_logger.error.assert_called_once_with(
            "JWT token missing in message headers"
        )
        ch.basic_nack.assert_called_once_with(delivery_tag="123", requeue=False)

    @patch(
        "finappsvc.notification_service.notificationsvc.authenticate_message",
        side_effect=Exception("Auth Error"),
    )
    @patch("finappsvc.notification_service.notificationsvc.logger")
    async def test_callback_authentication_failure(
        self, mock_logger, mock_authenticate_message
    ):
        # Arrange
        ch = MagicMock()
        method = MagicMock(delivery_tag="123")
        properties = MagicMock(headers={"Authorization": "invalid_token"})
        body = b"test_message"

        # Act
        await callback(ch, method, properties, body)

        # Assert
        mock_logger.error.assert_called_once_with(
            "Failed to process message: Auth Error"
        )
        ch.basic_nack.assert_called_once_with(delivery_tag="123", requeue=False)


if __name__ == "__main__":
    unittest.main()
