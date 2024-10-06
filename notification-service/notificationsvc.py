import logging
import sys
from common.database import connect_to_mongodb
from common.auth import authenticate_message
from common.consumer import start_consuming
from datetime import datetime


# Set up logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("notification_service.log"),
    ],
)
logger = logging.getLogger(__name__)

QUEUES = ["application_submitted", "user_activity"]
analytics_collection = connect_to_mongodb()


async def log_event(username: str, event: str):
    try:
        logger.info(f"Logging event: {event} for user: {username}")
        analytics_data = {
            "username": username,
            "event": event,
            "timestamp": datetime.utcnow(),
        }
        result = await analytics_collection.insert_one(analytics_data)
        logger.info(
            f"Event logged successfully for user: {username}. Inserted ID: {result.inserted_id}"
        )
    except Exception as e:
        logger.error(f"Failed to log event for {username}: {e}")


async def callback(ch, method, properties, body):
    try:
        message = body.decode("utf-8")
        if properties.headers is None:
            logger.error("No headers found in the message")
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            return

        token = properties.headers.get("Authorization")
        if not token:
            logger.error("JWT token missing in message headers")
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            return

        logger.info(f"JWT Token being received : {token}")
        username = authenticate_message(token)
        logger.info(f"Message received from queue: {message}")
        await log_event(username, f"Notification processed for {message}")

        ch.basic_ack(delivery_tag=method.delivery_tag)
        logger.info(f"Message from {username} processed successfully.")

    except Exception as e:
        logger.error(f"Failed to process message: {e}")
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)


if __name__ == "__main__":
    logger.info("Starting notification service...")
    try:
        start_consuming(QUEUES, callback)
    except KeyboardInterrupt:
        logger.info("Notification service interrupted and shutting down.")
    except Exception as e:
        logger.error(f"Unexpected error in notification service: {e}")
