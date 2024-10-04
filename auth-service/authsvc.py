import logging
import os
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
import pika
import bcrypt
from datetime import timedelta, datetime
from common.jwt_handler import ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token, get_current_user

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI()

# Read MongoDB URI and RabbitMQ URI from environment variables
MONGODB_URI = os.getenv("MONGODB_URI")
RABBITMQ_URI = os.getenv("RABBITMQ_URI")

# Ensure that MONGODB_URI is present
if not MONGODB_URI:
    raise ValueError("MONGODB_URI not set in environment variables or is empty!")

# Log the MongoDB URI
logger.info(f"Connecting to MongoDB at {MONGODB_URI}")

# Initialize MongoDB connection
try:
    client = AsyncIOMotorClient(MONGODB_URI)
    db = client['root']
    users_collection = db['users']
    logger.info("Connected to MongoDB successfully.")
except Exception as e:
    logger.error(f"Failed to connect to MongoDB: {e}")
    raise e

# RabbitMQ setup
def publish_message(queue, message):
    try:
        logger.info(f"Connecting to RabbitMQ at {RABBITMQ_URI}")
        connection = pika.BlockingConnection(pika.URLParameters(RABBITMQ_URI))
        channel = connection.channel()
        channel.queue_declare(queue=queue)
        logger.info(f"Queue '{queue}' declared. Publishing message...")
        channel.basic_publish(exchange='', routing_key=queue, body=message)
        logger.info(f"Message published to queue '{queue}': {message}")
        connection.close()
        logger.info(f"Closed RabbitMQ connection after publishing.")
    except Exception as e:
        logger.error(f"Failed to publish message to RabbitMQ: {e}")

# Publish analytics event for login
def publish_analytics_event(queue, message):
    try:
        logger.info(f"Publishing analytics event to RabbitMQ at {RABBITMQ_URI}")
        connection = pika.BlockingConnection(pika.URLParameters(RABBITMQ_URI))
        channel = connection.channel()
        channel.queue_declare(queue=queue)
        logger.info(f"Queue '{queue}' declared for analytics. Publishing event...")
        channel.basic_publish(exchange='', routing_key=queue, body=message)
        logger.info(f"Analytics event published to queue '{queue}': {message}")
        connection.close()
        logger.info(f"Closed RabbitMQ connection after publishing analytics event.")
    except Exception as e:
        logger.error(f"Failed to publish analytics event: {e}")

class User(BaseModel):
    username: str
    password: str

# Signup endpoint with JWT generation
@app.post("/signup")
async def signup(user: User):
    logger.info(f"Signup request received for user: {user.username}")
    
    # Check if the user already exists
    user_exists = await users_collection.find_one({"username": user.username})
    if user_exists:
        logger.warning(f"User already exists: {user.username}")
        raise HTTPException(status_code=400, detail="User already exists")
    
    try:
        # Hash the user's password and save the user to MongoDB
        hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
        await users_collection.insert_one({"username": user.username, "password": hashed_password})
        logger.info(f"User {user.username} created successfully")

        # Publish "user_registered" event to RabbitMQ
        publish_message("user_registered", user.username)

        # Generate JWT token for the user using the shared function
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
        
        logger.info(f"User {user.username} registered successfully, JWT generated")
        return {"message": "User registered", "access_token": access_token, "token_type": "bearer"}
    
    except Exception as e:
        logger.error(f"Signup failed for user {user.username}: {e}")
        raise HTTPException(status_code=500, detail="Failed to register user")

# Login endpoint with JWT generation
@app.post("/login")
async def login(user: User):
    try:
        logger.info(f"Login request received for user: {user.username}")
        db_user = await users_collection.find_one({"username": user.username})
        
        if not db_user:
            logger.warning(f"User {user.username} not found")
            raise HTTPException(status_code=400, detail="Invalid credentials")
        
        # Ensure stored password is bytes
        db_password = db_user['password']
        if isinstance(db_password, str):
            db_password = db_password.encode('utf-8')

        if not bcrypt.checkpw(user.password.encode('utf-8'), db_password):
            logger.warning(f"Invalid login attempt for user: {user.username}")
            raise HTTPException(status_code=400, detail="Invalid credentials")
        
        # Generate JWT token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
        
        logger.info(f"User {user.username} logged in successfully, JWT generated")
        
        # Publish an analytics event for the login
        analytics_message = f"User {user.username} logged in at {datetime.utcnow().isoformat()}"
        publish_analytics_event("user_activity", analytics_message)

        return {"access_token": access_token, "token_type": "bearer"}
    except Exception as e:
        logger.error(f"Login failed for user {user.username}: {e}")
        raise HTTPException(status_code=500, detail="Failed to login")
