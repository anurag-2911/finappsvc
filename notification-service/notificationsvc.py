from fastapi import HTTPException
import pika
import logging
import sys
from time import sleep
import sys
import os

# Add the parent directory (finappsvc) to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from common.jwt_handler import get_current_user, jwt, JWTError, JWT_SECRET_KEY, JWT_ALGORITHM

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

# RabbitMQ connection parameters and queue name

QUEUE_NAME = 'application_submitted'

def send_notification(message: str):
    """
    Simulates sending a notification (e.g., email, SMS) based on the received message.
    :param message: The message to be used for the notification.
    """
    try:
        logger.info(f"Preparing to send notification for message: {message}")
        # Simulate sending a notification (e.g., email, SMS, etc.)
        logger.info(f"Notification sent successfully for message: {message}")
    except Exception as e:
        logger.error(f"Failed to send notification: {e}")

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

def callback(ch, method, properties, body):
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

        # Authenticate the JWT token before processing
        username = authenticate_message(token)

        logger.info(f"Message received from queue: {message}")
        send_notification(message)

        # Acknowledge the message only if processing succeeds
        ch.basic_ack(delivery_tag=method.delivery_tag)
        logger.info(f"Message from {username} processed successfully.")

    except Exception as e:
        logger.error(f"Failed to process message: {e}")
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)  # Reject and don't requeue

def start_consuming(queue):
    """
    Establishes a connection to RabbitMQ and starts consuming messages from the specified queue.
    :param queue: The name of the queue to consume messages from.
    """
    while True:
        try:
            logger.info(f"Attempting to connect to RabbitMQ at {RABBITMQ_URI}")
            connection = pika.BlockingConnection(pika.URLParameters(RABBITMQ_URI))
            channel = connection.channel()

            # Ensure the queue exists before consuming
            channel.queue_declare(queue=queue)
            logger.info(f"Queue '{queue}' declared and ready for consumption.")

            # Start consuming messages with JWT validation
            channel.basic_consume(queue=queue, on_message_callback=callback)
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
        start_consuming(QUEUE_NAME)
    except KeyboardInterrupt:
        logger.info("Notification service interrupted and shutting down.")
    except Exception as e:
        logger.error(f"Unexpected error in notification service: {e}")
