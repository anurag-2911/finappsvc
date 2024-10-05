import logging
import pika
from fastapi import HTTPException

logger = logging.getLogger(__name__)

def publish_message(rabbitmq_uri, queue, message, token=None):
    try:
        logger.info(f"Publishing message to RabbitMQ at {rabbitmq_uri} for queue: {queue}")
        connection = pika.BlockingConnection(pika.URLParameters(rabbitmq_uri))
        channel = connection.channel()
        channel.queue_declare(queue=queue)
        properties = pika.BasicProperties(headers={'Authorization': token}) if token else None
        channel.basic_publish(exchange='', routing_key=queue, body=message, properties=properties)
        connection.close()
        logger.info(f"Message published to queue '{queue}': {message}")
    except Exception as e:
        logger.error(f"Failed to publish message to RabbitMQ: {e}")
        raise HTTPException(status_code=500, detail="Failed to publish message to RabbitMQ")
    
def connect_to_rabbitmq(rabbitmq_uri):
    try:
        logger.info(f"Connecting to RabbitMQ at {rabbitmq_uri}")
        connection = pika.BlockingConnection(pika.URLParameters(rabbitmq_uri))
        channel = connection.channel()
        return connection, channel
    except Exception as e:
        logger.error(f"Failed to connect to RabbitMQ: {e}")
        raise e
    
# Function to publish a message to a queue
def publish_to_queue(channel, queue, message, token=None):
    try:
        channel.queue_declare(queue=queue)
        logger.info(f"Queue '{queue}' declared. Publishing message...")

        properties = pika.BasicProperties(headers={'Authorization': token}) if token else None
        channel.basic_publish(exchange='', routing_key=queue, body=message, properties=properties)

        logger.info(f"Message published to queue '{queue}': {message}")
    except Exception as e:
        logger.error(f"Failed to publish message to RabbitMQ: {e}")

# Function to close the RabbitMQ connection
def close_rabbitmq_connection(connection):
    try:
        connection.close()
        logger.info(f"Closed RabbitMQ connection.")
    except Exception as e:
        logger.error(f"Failed to close RabbitMQ connection: {e}")
