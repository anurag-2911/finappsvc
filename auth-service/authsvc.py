import logging
import os
from fastapi import FastAPI, HTTPException, Depends, Request
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
import pika
import bcrypt
from datetime import timedelta, datetime
from common.jwt_handler import ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token, get_current_user
from fastapi.middleware.cors import CORSMiddleware

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: Adjust this with frontend's URL for the security
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Middleware to log requests
@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info(f"Request: {request.method} {request.url}")
    body = await request.body()
    logger.info(f"Request body: {body.decode('utf-8')}")
    response = await call_next(request)
    logger.info(f"Response status: {response.status_code}")
    return response

# Read MongoDB URI and RabbitMQ URI from environment variables
MONGODB_URI = os.getenv("MONGODB_URI")
RABBITMQ_URI = os.getenv("RABBITMQ_URI")

# Ensure that MONGODB_URI is present
if not MONGODB_URI:
    raise ValueError("MONGODB_URI not set in environment variables or is empty!")

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
def publish_message(queue, message, token=None):
    try:
        logger.info(f"Connecting to RabbitMQ at {RABBITMQ_URI}")
        connection = pika.BlockingConnection(pika.URLParameters(RABBITMQ_URI))
        channel = connection.channel()
        channel.queue_declare(queue=queue)
        logger.info(f"Queue '{queue}' declared. Publishing message...")

        # Include JWT token in message headers if token is provided
        properties = pika.BasicProperties(headers={'Authorization': token}) if token else None
        channel.basic_publish(exchange='', routing_key=queue, body=message, properties=properties)

        logger.info(f"Message published to queue '{queue}': {message}")
        connection.close()
        logger.info(f"Closed RabbitMQ connection after publishing.")
    except Exception as e:
        logger.error(f"Failed to publish message to RabbitMQ: {e}")

# Publish analytics event for login
def publish_analytics_event(queue, message, token=None):
    try:
        logger.info(f"JWT Token being published: {token}")
        logger.info(f"Publishing analytics event to RabbitMQ at {RABBITMQ_URI}")
        connection = pika.BlockingConnection(pika.URLParameters(RABBITMQ_URI))
        channel = connection.channel()
        channel.queue_declare(queue=queue)
        logger.info(f"Queue '{queue}' declared for analytics. Publishing event...")

        # Ensure token is always passed in message headers
        properties = pika.BasicProperties(headers={'Authorization': token}) if token else None
        
        if properties is None:
            logger.error(f"JWT Token is missing! Message will not have headers.")

        # Publish the message with the headers
        channel.basic_publish(exchange='', routing_key=queue, body=message, properties=properties)

        logger.info(f"Analytics event published to queue '{queue}': {message}")
        connection.close()
        logger.info(f"Closed RabbitMQ connection after publishing analytics event.")
    except Exception as e:
        logger.error(f"Failed to publish analytics event: {e}")

# Pydantic model for user input
class User(BaseModel):
    username: str
    password: str

# Signup endpoint with JWT generation
@app.post("/auth-service/signup")
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

        # Generate JWT token for the user using the shared function
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
        
        # Publish "user_registered" event to RabbitMQ, with JWT token in headers
        publish_message("user_registered", user.username, token=access_token)

        logger.info(f"User {user.username} registered successfully, JWT generated")
        return {"message": "User registered", "access_token": access_token, "token_type": "bearer"}
    
    except Exception as e:
        logger.error(f"Signup failed for user {user.username}: {e}")
        raise HTTPException(status_code=500, detail="Failed to register user")

# Login endpoint with JWT generation
@app.post("/auth-service/login")
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
        
        # Publish an analytics event for the login, passing the token along
        analytics_message = f"User {user.username} logged in at {datetime.utcnow().isoformat()}"
        publish_analytics_event("user_activity", analytics_message, token=access_token)

        return {"access_token": access_token, "token_type": "bearer"}
    except Exception as e:
        logger.error(f"Login failed for user {user.username}: {e}")
        raise HTTPException(status_code=500, detail="Failed to login")

