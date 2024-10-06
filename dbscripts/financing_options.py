import motor.motor_asyncio
import logging
import asyncio
import os

# Set up logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# MongoDB connection
MONGODB_URI = os.getenv("MONGODB_URI")
client = motor.motor_asyncio.AsyncIOMotorClient(MONGODB_URI)
db = client["root"]  # Use your MongoDB database

# Updated Financing options data based on the UI
financing_options_data = [
    {
        "option_name": "Home Loans",
        "interest_rate": 2.8,
        "duration_months": 240,
        "max_amount": 1000000,
        "description": "Get the best deals on home loans with low-interest rates.",
        "eligibility_criteria": {"min_income": 60000, "credit_score": 720},
    },
    {
        "option_name": "Car Loans",
        "interest_rate": 3.5,
        "duration_months": 60,
        "max_amount": 50000,
        "description": "Drive your dream car with affordable car loans.",
        "eligibility_criteria": {"min_income": 40000, "credit_score": 650},
    },
    {
        "option_name": "Education Loans",
        "interest_rate": 3.0,
        "duration_months": 120,
        "max_amount": 80000,
        "description": "Secure your future with low-interest education loans.",
        "eligibility_criteria": {"min_income": 30000, "credit_score": 600},
    },
    {
        "option_name": "Personal Loans",
        "interest_rate": 5.0,
        "duration_months": 36,
        "max_amount": 30000,
        "description": "Personal loans for all your needs with flexible repayment options.",
        "eligibility_criteria": {"min_income": 25000, "credit_score": 620},
    },
    {
        "option_name": "Business Loans",
        "interest_rate": 4.5,
        "duration_months": 72,
        "max_amount": 100000,
        "description": "Get financing options to grow your business.",
        "eligibility_criteria": {"min_income": 100000, "credit_score": 700},
    },
]


# Function to insert updated data into financing_options collection
async def populate_financing_options():
    try:
        logger.info("Populating financing_options collection with sample data...")
        await db["financing_options"].insert_many(financing_options_data)
        logger.info("Successfully populated financing_options collection.")
    except Exception as e:
        logger.error(
            f"Error occurred while populating financing_options collection: {e}"
        )


# Run the populate function
if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(populate_financing_options())
    loop.close()
