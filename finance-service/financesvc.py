import logging
import os
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
import pika
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
from bson import ObjectId
from common.jwt_handler import ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token, get_current_user

# Set up logging with more detailed settings
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# MongoDB and RabbitMQ URIs from environment
MONGODB_URI = os.getenv("MONGODB_URI")
RABBITMQ_URI = os.getenv("RABBITMQ_URI")
logger.info(f"Connecting to MongoDB at {MONGODB_URI}")
logger.info(f"Connecting to RabbitMQ at {RABBITMQ_URI}")

try:
    client = AsyncIOMotorClient(MONGODB_URI)
    db = client['root']
    applications_collection = db['applications']
    financing_options_collection = db['financing_options']
    users_collection = db['users']
    logger.info("Successfully connected to MongoDB and initialized collections.")
except Exception as e:
    logger.error(f"Failed to connect to MongoDB: {e}")
    raise HTTPException(status_code=500, detail="Failed to connect to MongoDB")

# RabbitMQ setup with JWT token in headers
def publish_message(queue, message, token):
    try:
        logger.info(f"Attempting to connect to RabbitMQ at {RABBITMQ_URI}")
        connection = pika.BlockingConnection(pika.URLParameters(RABBITMQ_URI))
        channel = connection.channel()
        channel.queue_declare(queue=queue)
        logger.info(f"Connected to RabbitMQ and declared queue: {queue}")

        # Include JWT token in the message headers
        properties = pika.BasicProperties(headers={'Authorization': token})

        channel.basic_publish(
            exchange='',
            routing_key=queue,
            body=message,
            properties=properties
        )

        logger.info(f"Message with JWT token published to queue {queue}: {message}")
        connection.close()
    except Exception as e:
        logger.error(f"Failed to publish message to RabbitMQ: {e}")
        raise HTTPException(status_code=500, detail="Failed to publish message to RabbitMQ")

class FinanceApplication(BaseModel):
    user: str
    amount: float

# Apply for financing
@app.post("/apply")
async def apply_finance(application: FinanceApplication, current_user: str = Depends(get_current_user)):
    try:
        logger.info(f"Finance application received for user: {application.user} with amount: {application.amount}")
        application_data = application.dict()
        application_data['status'] = 'pending'
        application_data['submitted_by'] = current_user  # Store the user who submitted the application

        logger.info(f"Inserting application into MongoDB for user: {current_user}")
        await applications_collection.insert_one(application_data)
        logger.info(f"Finance application by {current_user} for {application.amount} successfully inserted into MongoDB.")

        # Generate a new JWT token to include in the message header
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        token = create_access_token(data={"sub": current_user}, expires_delta=access_token_expires)

        # Publish "application_submitted" event with JWT token in the header
        publish_message("application_submitted", f"Application by {current_user} for {application.amount}", token)
        logger.info(f"Event 'application_submitted' published for user: {current_user}, amount: {application.amount}")

        return {"message": "Finance application submitted", "submitted_by": current_user}
    except Exception as e:
        logger.error(f"Failed to submit finance application for {current_user}: {e}")
        raise HTTPException(status_code=500, detail="Failed to submit finance application")

# Helper function to serialize MongoDB ObjectId
def serialize_document(document):
    document['_id'] = str(document['_id'])  # Convert ObjectId to string
    return document

# Check application status
@app.get("/status/{user}")
async def check_status(user: str, current_user: str = Depends(get_current_user)):
    try:
        logger.info(f"Status check request received for user: {user} by current user: {current_user}")
        if user != current_user:
            logger.warning(f"Unauthorized attempt by {current_user} to access {user}'s applications.")
            raise HTTPException(status_code=403, detail="You are not authorized to view this data")

        logger.info(f"Fetching applications for user: {current_user}")
        applications = await applications_collection.find({"submitted_by": current_user}).to_list(None)

        if not applications:
            logger.info(f"No applications found for user: {current_user}")
            return {"message": "No finance applications found"}

        applications = [serialize_document(app) for app in applications]
        logger.info(f"Applications found for user: {current_user}")
        return applications
    except Exception as e:
        logger.error(f"Failed to retrieve applications for {current_user}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve applications")

# Update application status (admin functionality)
@app.put("/update_status/{user}/{status}")
async def update_application_status(user: str, status: str, current_user: str = Depends(get_current_user)):
    try:
        logger.info(f"Status update request received for user: {user} to {status} by admin: {current_user}")
        if status not in ["approved", "denied"]:
            logger.warning(f"Invalid status update attempted by {current_user}: {status}")
            raise HTTPException(status_code=400, detail="Invalid status")

        logger.info(f"Updating application status for user: {user} to {status}")
        update_result = await applications_collection.update_many({"submitted_by": user}, {"$set": {"status": status}})
        if update_result.matched_count == 0:
            logger.warning(f"No applications found for user: {user}")
            return {"message": "No applications found to update"}

        logger.info(f"Application status for {user} updated to {status} by {current_user}")
        return {"message": f"Status updated to {status}"}
    except Exception as e:
        logger.error(f"Failed to update status for {user}: {e}")
        raise HTTPException(status_code=500, detail="Failed to update status")

# Dashboard Info (new endpoint)
@app.get("/dashboard-info")
async def dashboard_info(current_user: str = Depends(get_current_user)):
    try:
        logger.info(f"Fetching dashboard info for user: {current_user}")
        applications = await applications_collection.find({"submitted_by": current_user}).to_list(None)

        application_summary = {
            "total_applications": len(applications),
            "approved": len([app for app in applications if app.get('status') == 'approved']),
            "denied": len([app for app in applications if app.get('status') == 'denied']),
            "pending": len([app for app in applications if app.get('status') == 'pending']),
        }

        logger.info(f"Dashboard info fetched for user: {current_user}")
        return {
            "username": current_user,
            "application_summary": application_summary
        }
    except Exception as e:
        logger.error(f"Failed to fetch dashboard info for {current_user}: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch dashboard info")

# Financing Options (new endpoint)
@app.get("/financing-options")
async def financing_options():
    try:
        logger.info("Fetching all financing options")
        financing_options = await financing_options_collection.find().to_list(None)
        financing_options = [serialize_document(option) for option in financing_options]

        if not financing_options:
            return {"message": "No financing options available"}

        logger.info("Financing options fetched successfully.")
        return financing_options
    except Exception as e:
        logger.error(f"Failed to fetch financing options: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch financing options")

# Admin-only: View all applications (new endpoint)
@app.get("/all-applications")
async def all_applications(current_user: str = Depends(get_current_user)):
    try:
        logger.info(f"Admin request received to fetch all applications by user: {current_user}")

        # Assuming admin's username is "admin", adjust logic based on actual authentication setup
        if current_user != "admin":
            logger.warning(f"Unauthorized attempt by {current_user} to access all applications.")
            raise HTTPException(status_code=403, detail="Admin access required")

        applications = await applications_collection.find().to_list(None)
        applications = [serialize_document(app) for app in applications]

        logger.info("All applications fetched successfully by admin.")
        return applications
    except Exception as e:
        logger.error(f"Failed to fetch all applications: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch all applications")

# Admin-only: View user list and their statuses (new endpoint)
@app.get("/user-list")
async def user_list(current_user: str = Depends(get_current_user)):
    try:
        logger.info(f"Admin request received to fetch user list by {current_user}")

        if current_user != "admin":
            logger.warning(f"Unauthorized attempt by {current_user} to access user list.")
            raise HTTPException(status_code=403, detail="Admin access required")

        users = await users_collection.find().to_list(None)
        users = [serialize_document(user) for user in users]

        logger.info("User list fetched successfully by admin.")
        return users
    except Exception as e:
        logger.error(f"Failed to fetch user list: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch user list")
