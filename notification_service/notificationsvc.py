import logging
import sys
import signal
import asyncio
from common.database import connect_to_mongodb
from common.auth import authenticate_message
from common.consumer import start_consuming
from datetime import datetime, timezone

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
client, analytics_collection = connect_to_mongodb()

# Flag to signal when to stop the service
stop_flag = asyncio.Event()


async def log_event(username: str, event: str):
    try:
        logger.info(f"Logging event: {event} for user: {username}")
        analytics_data = {
            "username": username,
            "event": event,
            "timestamp": datetime.now(timezone.utc),
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


async def shutdown():
    """Ensure that the MongoDB client is closed on shutdown."""
    logger.info("Shutting down notification service...")
    client.close()
    logger.info("MongoDB client closed.")
    stop_flag.set()


def signal_handler(signal_received, frame):
    """Handle termination signals from Kubernetes."""
    logger.info(
        f"Termination signal ({signal_received}) received. Preparing to shut down..."
    )
    asyncio.run(shutdown())


def register_signal_handlers():
    """Register signal handlers to catch Kubernetes termination signals."""
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


if __name__ == "__main__":
    logger.info("Starting notification service...")
    register_signal_handlers()

    try:
        # Start consuming the queues
        start_consuming(QUEUES, callback)
        asyncio.run(stop_flag.wait())  # Wait for the stop flag to be set
    except Exception as e:
        logger.error(f"Unexpected error in notification service: {e}")
        asyncio.run(shutdown())  # Ensure MongoDB client is closed in case of error
