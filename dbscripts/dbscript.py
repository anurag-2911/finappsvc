import motor.motor_asyncio
import logging
from bson import ObjectId
import os

# Set up detailed logging
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# MongoDB connection setup
MONGODB_URI = os.getenv("MONGODB_URI")
client = motor.motor_asyncio.AsyncIOMotorClient(MONGODB_URI)
db = client["root"]


# Ensure collections exist with detailed logs
async def initialize_collections():
    try:
        logger.info("Initializing collections in MongoDB...")
        collections = await db.list_collection_names()
        logger.debug(f"Existing collections: {collections}")

        # Check and create 'users' collection
        if "users" not in collections:
            await db.create_collection("users")
            await db["users"].create_index("username", unique=True)
            logger.info("Created 'users' collection with unique index on 'username'.")
        else:
            logger.info("'users' collection already exists.")

        # Check and create 'applications' collection
        if "applications" not in collections:
            await db.create_collection("applications")
            logger.info("Created 'applications' collection.")
        else:
            logger.info("'applications' collection already exists.")

        # Check and create 'financing_options' collection
        if "financing_options" not in collections:
            await db.create_collection("financing_options")
            logger.info("Created 'financing_options' collection.")
        else:
            logger.info("'financing_options' collection already exists.")

        # Check and create 'user_analytics' collection
        if "user_analytics" not in collections:
            await db.create_collection("user_analytics")
            logger.info("Created 'user_analytics' collection.")

            # Optionally, add a sample analytics entry for testing
            sample_analytics_data = {
                "username": "admin",
                "event": "logged in",
                "timestamp": "2024-10-04T00:00:00Z",
            }
            await db["user_analytics"].insert_one(sample_analytics_data)
            logger.info("Inserted sample data into 'user_analytics' collection.")
        else:
            logger.info("'user_analytics' collection already exists.")

        # Add sample data to 'users' if admin user doesn't exist
        logger.info("Checking for admin user...")
        admin_user = await db["users"].find_one({"username": "admin"})
        if not admin_user:
            logger.info("Admin user not found, creating a new admin user.")
            await db["users"].insert_one(
                {
                    "username": "admin",
                    "password": "hashedpassword123",
                    "email": "admin@example.com",
                    "role": "admin",
                }
            )
            logger.info("Admin user created.")
        else:
            logger.info("Admin user already exists, skipping creation.")

        logger.info("All collections initialized successfully.")

    except Exception as e:
        logger.error(f"Error during collection initialization: {e}")
        raise e


# Run the initialization process
import asyncio

logger.info("Starting database initialization process...")
asyncio.run(initialize_collections())
logger.info("Database initialization complete.")
