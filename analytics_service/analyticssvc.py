from fastapi import FastAPI, HTTPException, Depends
import logging
from common.jwt_handler import get_current_user
from common.mongodb_handler import get_mongodb_client

app = FastAPI()

# Set up logging with more detailed settings
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


# Connect to MongoDB
try:
    client = get_mongodb_client()
    db = client["root"]
    analytics_collection = db["user_analytics"]
    users_collection = db["users"]
    logger.info("Successfully connected to MongoDB for analytics.")
except Exception as e:
    logger.error(f"Failed to connect to MongoDB: {e}")
    raise HTTPException(status_code=500, detail="Failed to connect to MongoDB")


# Admin-only: View analytics data
@app.get("/analytics")
async def get_analytics(current_user: str = Depends(get_current_user)):
    try:
        # Ensure that only admin users can access this endpoint
        user = await users_collection.find_one({"username": current_user})
        if not user or user.get("role") != "admin":
            logger.warning(
                f"Unauthorized attempt by {current_user} to access analytics data."
            )
            raise HTTPException(status_code=403, detail="Admin access required")

        logger.info(f"Analytics request received from admin user: {current_user}")

        # Fetch all analytics events
        analytics_data = await analytics_collection.find().to_list(None)

        if not analytics_data:
            logger.info(f"No analytics data available for admin user: {current_user}")
            return {"message": "No analytics data available"}

        # Summarize analytics data
        logins = [event for event in analytics_data if "logged in" in event["event"]]
        finance_checks = [
            event
            for event in analytics_data
            if "checked financing options" in event["event"]
        ]

        analytics_summary = {
            "total_events": len(analytics_data),
            "total_logins": len(logins),
            "total_financing_option_checks": len(finance_checks),
            "logins_per_user": {},
            "financing_checks_per_user": {},
        }

        # Count logins and financing option checks per user
        for event in logins:
            username = event["username"]
            analytics_summary["logins_per_user"][username] = (
                analytics_summary["logins_per_user"].get(username, 0) + 1
            )

        for event in finance_checks:
            username = event["username"]
            analytics_summary["financing_checks_per_user"][username] = (
                analytics_summary["financing_checks_per_user"].get(username, 0) + 1
            )

        logger.info(
            f"Analytics data fetched successfully for admin user: {current_user}"
        )
        return analytics_summary
    except Exception as e:
        logger.error(f"Failed to retrieve analytics data for {current_user}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve analytics data")
