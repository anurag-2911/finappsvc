from motor.motor_asyncio import AsyncIOMotorClient
import logging
import os

MONGODB_URI = os.getenv("MONGODB_URI")
logger = logging.getLogger(__name__)

def connect_to_mongodb():
    try:
        client = AsyncIOMotorClient(MONGODB_URI)
        db = client['root']
        analytics_collection = db['user_analytics']
        logger.info("Successfully connected to MongoDB for analytics.")
        return analytics_collection
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        raise