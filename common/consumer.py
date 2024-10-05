import os
import pika
import logging
import asyncio
import threading
from time import sleep

RABBITMQ_URI = os.getenv("RABBITMQ_URI")
logger = logging.getLogger(__name__)

def start_consuming(queues, callback):
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

            for queue in queues:
                channel.queue_declare(queue=queue)
                logger.info(f"Queue '{queue}' declared and ready for consumption.")

            def on_message(channel, method, properties, body):
                asyncio.run_coroutine_threadsafe(
                    callback(channel, method, properties, body), async_loop
                )

            for queue in queues:
                channel.basic_consume(queue=queue, on_message_callback=on_message)
                logger.info(f"Started consuming messages from queue: {queue}")

            channel.start_consuming()

        except pika.exceptions.AMQPConnectionError as e:
            logger.error(f"Connection to RabbitMQ failed: {e}")
            logger.info("Retrying in 5 seconds...")
            sleep(5)

        except Exception as e:
            logger.error(f"An error occurred: {e}")
            logger.info("Retrying in 5 seconds...")
            sleep(5)