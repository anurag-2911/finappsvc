from fastapi import HTTPException
from common.jwt_handler import jwt, JWTError, JWT_SECRET_KEY, JWT_ALGORITHM
import logging

logger = logging.getLogger(__name__)

def authenticate_message(token):
    try:
        logger.info("Authenticating JWT token from message...")
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        if username:
            logger.info(f"Token authenticated successfully for user: {username}")
            return username
        else:
            raise JWTError("Invalid token payload")
    except JWTError as e:
        logger.error(f"JWT authentication failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")