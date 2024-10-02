import logging
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
import pika
import bcrypt
from urllib.parse import quote_plus
from datetime import timedelta
from common.jwt_handler import ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token, get_current_user

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)



app = FastAPI()

# MongoDB setup
username = quote_plus("root")
password = quote_plus("anurag@2911X")  
mongo_uri = f"mongodb+srv://{username}:{password}@mongocluster.9xaal.mongodb.net/"
logger.info(f"Connecting to MongoDB at {mongo_uri}")
client = AsyncIOMotorClient(mongo_uri)
db = client['root']
users_collection = db['users']

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

class User(BaseModel):
    username: str
    password: str

# Signup endpoint with JWT generation
@app.post("/signup")
async def signup(user: User):
    try:
        logger.info(f"Signup request received for user: {user.username}")
        user_exists = await users_collection.find_one({"username": user.username})
        if user_exists:
            logger.warning(f"User already exists: {user.username}")
            raise HTTPException(status_code=400, detail="User already exists")
        
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
        if not db_user or not bcrypt.checkpw(user.password.encode('utf-8'), db_user['password']):
            logger.warning(f"Invalid login attempt for user: {user.username}")
            raise HTTPException(status_code=400, detail="Invalid credentials")
        
        # Generate JWT token for the user using the shared function
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
        logger.info(f"User {user.username} logged in successfully, JWT generated")
        return {"access_token": access_token, "token_type": "bearer"}
    except Exception as e:
        logger.error(f"Login failed for user {user.username}: {e}")
        raise HTTPException(status_code=500, detail="Failed to login")

# Protected route example
@app.get("/dashboard")
async def dashboard(current_user: User = Depends(get_current_user)):
    logger.info(f"Dashboard accessed by user: {current_user['username']}")
    return {"message": f"Welcome {current_user['username']}!"}
