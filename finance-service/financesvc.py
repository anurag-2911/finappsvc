import logging
from fastapi import FastAPI, HTTPException, Depends, Query
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timedelta
from bson import ObjectId
from common.jwt_handler import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    create_access_token,
    get_current_user,
)
from common.rabbitmq_handler import publish_message
from common.mongodb_handler import get_mongodb_client
from math import ceil

# Initialize FastAPI app
app = FastAPI()

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Set up logging
def setup_logging():
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )
    return logging.getLogger(__name__)


logger = setup_logging()

client = get_mongodb_client()
db = client["root"]
applications_collection = db["applications"]
financing_options_collection = db["financing_options"]
users_collection = db["users"]


# Models
class FinanceApplication(BaseModel):
    loan_types: list[str]
    amount: float
    purpose: str


class FinancingOptionSelection(BaseModel):
    option_id: str


# Helper functions
def serialize_document(document):
    document["_id"] = str(document["_id"])
    return document


# Helper function to check if the current user is admin
async def verify_admin(current_user: str):
    user = await users_collection.find_one({"username": current_user})
    if not user or user.get("role") != "admin":
        logger.warning(
            f"Unauthorized attempt by {current_user}. Admin privileges required."
        )
        raise HTTPException(status_code=403, detail="Admin privileges required")


# Endpoints
@app.post("/apply")
async def apply_finance(
    application: FinanceApplication, current_user: str = Depends(get_current_user)
):
    try:
        application_data = application.dict()
        application_data["status"] = "pending"
        application_data["submitted_by"] = current_user
        await applications_collection.insert_one(application_data)
        token = create_access_token(
            data={"sub": current_user},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        )
        publish_message(
            "application_submitted",
            f"Application by {current_user} for {application.amount}",
            token,
        )
        return {
            "message": "Finance application submitted",
            "submitted_by": current_user,
        }
    except Exception as e:
        logger.error(f"Failed to submit finance application for {current_user}: {e}")
        raise HTTPException(
            status_code=500, detail="Failed to submit finance application"
        )


@app.get("/status")
async def check_status(current_user: str = Depends(get_current_user)):
    """
    Fetches the finance applications of the current user.
    """
    try:
        applications = await applications_collection.find(
            {"submitted_by": current_user}
        ).to_list(None)
        if not applications:
            return {"message": "No finance applications found"}
        return [serialize_document(app) for app in applications]
    except Exception as e:
        logger.error(f"Failed to retrieve applications for {current_user}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve applications")


@app.put("/update_status/{user}/{status}")
async def update_application_status(
    user: str, status: str, current_user: str = Depends(get_current_user)
):
    try:
        if status not in ["approved", "denied"]:
            raise HTTPException(status_code=400, detail="Invalid status")
        update_result = await applications_collection.update_many(
            {"submitted_by": user}, {"$set": {"status": status}}
        )
        if update_result.matched_count == 0:
            return {"message": "No applications found to update"}
        return {"message": f"Status updated to {status}"}
    except Exception as e:
        logger.error(f"Failed to update status for {user}: {e}")
        raise HTTPException(status_code=500, detail="Failed to update status")


@app.get("/dashboard-info")
async def dashboard_info(current_user: str = Depends(get_current_user)):
    try:
        applications = await applications_collection.find(
            {"submitted_by": current_user}
        ).to_list(None)
        application_summary = {
            "total_applications": len(applications),
            "approved": len(
                [app for app in applications if app.get("status") == "approved"]
            ),
            "denied": len(
                [app for app in applications if app.get("status") == "denied"]
            ),
            "pending": len(
                [app for app in applications if app.get("status") == "pending"]
            ),
        }
        return {"username": current_user, "application_summary": application_summary}
    except Exception as e:
        logger.error(f"Failed to fetch dashboard info for {current_user}: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch dashboard info")


@app.get("/financing-options")
async def financing_options(current_user: str = Depends(get_current_user)):
    try:
        logger.info(f"User {current_user} is fetching financing options.")
        financing_options = await financing_options_collection.find().to_list(None)
        if not financing_options:
            logger.info("No financing options found in the database.")
            return {"message": "No financing options available"}
        logger.info(f"Found {len(financing_options)} financing options.")
        publish_message(
            "user_activity",
            f"User {current_user} checked financing options at {datetime.utcnow().isoformat()}",
        )
        return [serialize_document(option) for option in financing_options]
    except Exception as e:
        logger.error(f"Failed to fetch financing options for user: {current_user}: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch financing options")


@app.post("/select-financing-option")
async def select_financing_option(
    selection: FinancingOptionSelection, current_user: str = Depends(get_current_user)
):
    try:
        selected_option = await financing_options_collection.find_one(
            {"_id": ObjectId(selection.option_id)}
        )
        if not selected_option:
            raise HTTPException(status_code=404, detail="Financing option not found")
        existing_selection = await db["user_financing_selections"].find_one(
            {"user": current_user}
        )
        if existing_selection:
            await db["user_financing_selections"].update_one(
                {"user": current_user},
                {
                    "$set": {
                        "selected_option": selected_option,
                        "updated_at": datetime.utcnow(),
                    }
                },
            )
        else:
            await db["user_financing_selections"].insert_one(
                {
                    "user": current_user,
                    "selected_option": selected_option,
                    "selected_at": datetime.utcnow(),
                }
            )
        publish_message(
            "financing_option_selected",
            f"User {current_user} selected financing option {selected_option['option_name']}",
            create_access_token({"sub": current_user}),
        )
        return {
            "message": f"Financing option {selected_option['option_name']} selected successfully",
            "selected_option": selected_option,
        }
    except Exception as e:
        logger.error(
            f"Failed to save financing option selection for user {current_user}: {e}"
        )
        raise HTTPException(
            status_code=500, detail="Failed to save financing option selection"
        )


# Endpoint to apply for financing
@app.post("/apply-finance")
async def apply_finance(
    application: FinanceApplication, current_user: str = Depends(get_current_user)
):
    try:
        # Prepare application data
        application_data = application.dict()
        application_data["status"] = "pending"
        application_data["submitted_by"] = current_user
        application_data["submitted_at"] = datetime.utcnow()

        # Insert application into MongoDB
        result = await applications_collection.insert_one(application_data)

        # Create and publish JWT token for message
        token = create_access_token(
            data={"sub": current_user},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        )
        publish_message(
            "application_submitted",
            f"Application by {current_user} for {application.amount}",
            token,
        )

        return {
            "message": "Finance application submitted",
            "application_id": str(result.inserted_id),
        }

    except Exception as e:
        logger.error(f"Failed to submit finance application for {current_user}: {e}")
        raise HTTPException(
            status_code=500, detail="Failed to submit finance application"
        )


# Models for pagination
class PaginatedResponse(BaseModel):
    data: list
    total_pages: int
    current_page: int
    total_items: int


# Endpoint to get applications for all users (Admin Panel) with pagination
@app.get("/admin/applications", response_model=PaginatedResponse)
async def get_all_applications(
    page: int = Query(1, ge=1),
    per_page: int = Query(10, ge=1, le=100),
    current_user: str = Depends(get_current_user),
):
    """
    Fetch all finance applications (Admin Panel).
    Supports pagination.
    """
    try:
        # Check if the current user is an admin
        await verify_admin(current_user)

        total_items = await applications_collection.count_documents({})
        total_pages = ceil(total_items / per_page)

        applications = (
            await applications_collection.find()
            .skip((page - 1) * per_page)
            .limit(per_page)
            .to_list(None)
        )

        serialized_applications = [serialize_document(app) for app in applications]

        return {
            "data": serialized_applications,
            "total_pages": total_pages,
            "current_page": page,
            "total_items": total_items,
        }

    except Exception as e:
        logger.error(f"Failed to retrieve applications: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve applications")


# Endpoint to update application status by admin
@app.put("/admin/update_status/{application_id}/{status}")
async def admin_update_application_status(
    application_id: str, status: str, current_user: str = Depends(get_current_user)
):
    """
    Allows admin to update the status of a finance application.
    """
    try:
        # Check if the current user is an admin
        await verify_admin(current_user)

        if status not in ["approved", "denied"]:
            raise HTTPException(status_code=400, detail="Invalid status")

        update_result = await applications_collection.update_one(
            {"_id": ObjectId(application_id)}, {"$set": {"status": status}}
        )

        if update_result.matched_count == 0:
            return {"message": "Application not found"}

        return {"message": f"Status updated to {status}"}

    except Exception as e:
        logger.error(f"Failed to update status for application {application_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to update status")
