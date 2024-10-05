import logging
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import bcrypt
from datetime import timedelta, datetime
from common.jwt_handler import ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token
from common.rabbitmq_handler import publish_message, publish_analytics_event
from common.mongodb_handler import get_mongodb_client  

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI()

# Initialize MongoDB connection
client = get_mongodb_client()
db = client['root']
users_collection = db['users']

class User(BaseModel):
    username: str
    password: str

async def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

async def verify_password(plain_password: str, hashed_password: bytes) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)

async def create_user(user: User):
    hashed_password = await hash_password(user.password)
    await users_collection.insert_one({"username": user.username, "password": hashed_password})
    logger.info(f"User {user.username} created successfully")

async def generate_jwt_token(username: str) -> str:
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return create_access_token(data={"sub": username}, expires_delta=access_token_expires)

@app.post("/signup")
async def signup(user: User):
    logger.info(f"Signup request received for user: {user.username}")
    
    user_exists = await users_collection.find_one({"username": user.username})
    if user_exists:
        logger.warning(f"User already exists: {user.username}")
        raise HTTPException(status_code=400, detail="User already exists")
    
    try:
        await create_user(user)
        access_token = await generate_jwt_token(user.username)
        
        publish_message("user_registered", user.username, token=access_token)

        logger.info(f"User {user.username} registered successfully, JWT generated")
        return {"message": "User registered", "access_token": access_token, "token_type": "bearer"}
    
    except Exception as e:
        logger.error(f"Signup failed for user {user.username}: {e}")
        raise HTTPException(status_code=500, detail="Failed to register user")

@app.post("/login")
async def login(user: User):
    try:
        logger.info(f"Login request received for user: {user.username}")
        db_user = await users_collection.find_one({"username": user.username})
        
        if not db_user:
            logger.warning(f"User {user.username} not found")
            raise HTTPException(status_code=400, detail="Invalid credentials")
        
        db_password = db_user['password']
        if isinstance(db_password, str):
            db_password = db_password.encode('utf-8')

        if not await verify_password(user.password, db_password):
            logger.warning(f"Invalid login attempt for user: {user.username}")
            raise HTTPException(status_code=400, detail="Invalid credentials")
        
        access_token = await generate_jwt_token(user.username)
        
        logger.info(f"User {user.username} logged in successfully, JWT generated")
        
        analytics_message = f"User {user.username} logged in at {datetime.utcnow().isoformat()}"
        publish_analytics_event("user_activity", analytics_message, token=access_token)

        return {"access_token": access_token, "token_type": "bearer"}
    except Exception as e:
        logger.error(f"Login failed for user {user.username}: {e}")
        raise HTTPException(status_code=500, detail="Failed to login")