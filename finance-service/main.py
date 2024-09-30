import logging
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
import pika
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import timedelta
from urllib.parse import quote_plus

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

SECRET_KEY = "your_secret_key"  # Replace this with a strong key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# MongoDB setup
username = quote_plus("root")
password = quote_plus("anurag@2911X")  
mongo_uri = f"mongodb+srv://{username}:{password}@mongocluster.9xaal.mongodb.net/"
logger.info(f"Connecting to MongoDB at {mongo_uri}")
client = AsyncIOMotorClient(mongo_uri)
db = client['root']
applications_collection = db['applications']

# RabbitMQ setup
def publish_message(queue, message):
    try:
        logger.info(f"Connecting to RabbitMQ at amqp://novell:novell@123@172.105.51.216:5672/")
        connection = pika.BlockingConnection(pika.URLParameters('amqp://novell:novell@123@172.105.51.216:5672/'))
        channel = connection.channel()
        channel.queue_declare(queue=queue)
        channel.basic_publish(exchange='', routing_key=queue, body=message)
        logger.info(f"Message published to queue {queue}: {message}")
        connection.close()
    except Exception as e:
        logger.error(f"Failed to publish message to RabbitMQ: {e}")

class FinanceApplication(BaseModel):
    user: str
    amount: float

# JWT token verification
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        logger.info(f"Token validated for user: {username}")
    except JWTError as e:
        logger.error(f"JWT validation error: {e}")
        raise credentials_exception
    
    return username

# Apply for financing
@app.post("/apply")
async def apply_finance(application: FinanceApplication, current_user: str = Depends(get_current_user)):
    try:
        application_data = application.dict()
        application_data['status'] = 'pending'
        application_data['submitted_by'] = current_user  # Store the user who submitted the application

        await applications_collection.insert_one(application_data)
        logger.info(f"Finance application by {current_user} for {application.amount} submitted.")

        # Publish "application_submitted" event
        publish_message("application_submitted", f"Application by {current_user} for {application.amount}")

        return {"message": "Finance application submitted", "submitted_by": current_user}
    except Exception as e:
        logger.error(f"Failed to submit finance application for {current_user}: {e}")
        raise HTTPException(status_code=500, detail="Failed to submit finance application")

# Check application status
@app.get("/status/{user}")
async def check_status(user: str, current_user: str = Depends(get_current_user)):
    try:
        if user != current_user:
            logger.warning(f"Unauthorized attempt by {current_user} to access {user}'s applications.")
            raise HTTPException(status_code=403, detail="You are not authorized to view this data")

        applications = await applications_collection.find({"submitted_by": current_user}).to_list(None)
        if not applications:
            logger.info(f"No applications found for user: {current_user}")
            return {"message": "No finance applications found"}

        logger.info(f"Applications found for user: {current_user}")
        return applications
    except Exception as e:
        logger.error(f"Failed to retrieve applications for {current_user}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve applications")

# Update application status (admin functionality)
@app.put("/update_status/{user}/{status}")
async def update_application_status(user: str, status: str, current_user: str = Depends(get_current_user)):
    try:
        if status not in ["approved", "denied"]:
            logger.warning(f"Invalid status update attempted by {current_user}: {status}")
            raise HTTPException(status_code=400, detail="Invalid status")

        update_result = await applications_collection.update_many({"submitted_by": user}, {"$set": {"status": status}})
        if update_result.matched_count == 0:
            logger.warning(f"No applications found for user: {user}")
            return {"message": "No applications found to update"}

        logger.info(f"Application status for {user} updated to {status} by {current_user}")
        return {"message": f"Status updated to {status}"}
    except Exception as e:
        logger.error(f"Failed to update status for {user}: {e}")
        raise HTTPException(status_code=500, detail="Failed to update status")
