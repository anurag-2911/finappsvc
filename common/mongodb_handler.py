import os
import logging
from motor.motor_asyncio import AsyncIOMotorClient

# Set up logging
logger = logging.getLogger(__name__)


def get_mongodb_client():
    # Read MongoDB URI from environment variables
    MONGODB_URI = os.getenv("MONGODB_URI")

    # Ensure that MONGODB_URI is present
    if not MONGODB_URI:
        raise ValueError("MONGODB_URI not set in environment variables or is empty!")
    
    # Initialize MongoDB connection
    try:
        client = AsyncIOMotorClient(MONGODB_URI)
        logger.info("Connected to MongoDB successfully.")
        return client
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        raise e
