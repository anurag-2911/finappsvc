from fastapi import HTTPException
import pika
import logging
import sys
from time import sleep
import os
from datetime import datetime
import asyncio  
import threading

# Add the parent directory (finappsvc) to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from common.jwt_handler import jwt, JWTError, JWT_SECRET_KEY, JWT_ALGORITHM
from motor.motor_asyncio import AsyncIOMotorClient

MONGODB_URI = os.getenv("MONGODB_URI")
RABBITMQ_URI = os.getenv("RABBITMQ_URI")

# Set up logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("notification_service.log")
    ]
)
logger = logging.getLogger(__name__)

# RabbitMQ queues
QUEUES = ['application_submitted', 'user_activity']

# Connect to MongoDB
try:
    client = AsyncIOMotorClient(MONGODB_URI)
    db = client['root']
    analytics_collection = db['user_analytics']
    logger.info("Successfully connected to MongoDB for analytics.")
except Exception as e:
    logger.error(f"Failed to connect to MongoDB: {e}")
    raise HTTPException(status_code=500, detail="Failed to connect to MongoDB")

async def log_event(username: str, event: str):
    """
    Logs the user activity into MongoDB for analytics purposes asynchronously.
    :param username: The username of the user.
    :param event: The event description.
    """
    try:
        logger.info(f"Logging event: {event} for user: {username}")
        analytics_data = {
            "username": username,
            "event": event,
            "timestamp": datetime.utcnow()
        }
        # Insert the event into the analytics collection asynchronously
        result = await analytics_collection.insert_one(analytics_data)
        logger.info(f"Event logged successfully for user: {username}. Inserted ID: {result.inserted_id}")
    except Exception as e:
        logger.error(f"Failed to log event for {username}: {e}")

def authenticate_message(token):
    """
    Authenticate the JWT token before processing the message.
    :param token: The JWT token included in the message properties.
    :return: Username if authenticated successfully, otherwise raise an error.
    """
    try:
        logger.info("Authenticating JWT token from message...")
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        if username:
            logger.info(f"Token authenticated successfully for user: {username}")
            return username
        else:
            raise JWTError("Invalid token payload")
    except JWTError as e:
        logger.error(f"JWT authentication failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")



async def callback(ch, method, properties, body):
    """
    Callback function for RabbitMQ to process incoming messages.
    Each message will contain a JWT token in the headers for authentication.
    :param ch: Channel.
    :param method: Method.
    :param properties: Message properties (contains headers with JWT token).
    :param body: Message content.
    """
    try:
        message = body.decode('utf-8')

        # Check if properties.headers exist
        if properties.headers is None:
            logger.error("No headers found in the message")
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)  # Reject and don't requeue
            return

        # Extract the JWT token from headers
        token = properties.headers.get('Authorization')

        if not token:
            logger.error("JWT token missing in message headers")
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)  # Reject and don't requeue
            return

        # Log received token for debugging
        logger.info(f"JWT Token being received : {token}")

        # Authenticate the JWT token before processing
        username = authenticate_message(token)

        logger.info(f"Message received from queue: {message}")
        await log_event(username, f"Notification processed for {message}")  # Async log_event

        # Acknowledge the message only if processing succeeds
        ch.basic_ack(delivery_tag=method.delivery_tag)
        logger.info(f"Message from {username} processed successfully.")

    except Exception as e:
        logger.error(f"Failed to process message: {e}")
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)  # Reject and don't requeue




def start_consuming(queues):
    """
    Establishes a connection to RabbitMQ and starts consuming messages from the specified queues.
    :param queues: List of queue names to consume messages from.
    """
    def run_async_loop(loop):
        asyncio.set_event_loop(loop)
        loop.run_forever()

    async_loop = asyncio.new_event_loop()
    threading.Thread(target=run_async_loop, args=(async_loop,)).start()

    while True:
        try:
            logger.info(f"Attempting to connect to RabbitMQ at {RABBITMQ_URI}")
            connection = pika.BlockingConnection(pika.URLParameters(RABBITMQ_URI))
            channel = connection.channel()

            # Ensure each queue exists before consuming
            for queue in queues:
                channel.queue_declare(queue=queue)
                logger.info(f"Queue '{queue}' declared and ready for consumption.")

            # Define an async wrapper around the callback
            def on_message(channel, method, properties, body):
                asyncio.run_coroutine_threadsafe(
                    callback(channel, method, properties, body), async_loop
                )

            # Start consuming messages with JWT validation for each queue
            for queue in queues:
                channel.basic_consume(queue=queue, on_message_callback=on_message)
                logger.info(f"Started consuming messages from queue: {queue}")

            channel.start_consuming()

        except pika.exceptions.AMQPConnectionError as e:
            logger.error(f"Connection to RabbitMQ failed: {e}")
            logger.info("Retrying in 5 seconds...")
            sleep(5)  # Retry after a short delay

        except Exception as e:
            logger.error(f"An error occurred: {e}")
            logger.info("Retrying in 5 seconds...")
            sleep(5)

if __name__ == "__main__":
    logger.info("Starting notification service...")
    try:
        start_consuming(QUEUES)  # Consume from both 'application_submitted' and 'user_activity' queues
    except KeyboardInterrupt:
        logger.info("Notification service interrupted and shutting down.")
    except Exception as e:
        logger.error(f"Unexpected error in notification service: {e}")
