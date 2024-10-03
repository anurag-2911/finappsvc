import motor.motor_asyncio
import logging
import asyncio
import os

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# MongoDB connection
MONGODB_URI = os.getenv("MONGODB_URI")
client = motor.motor_asyncio.AsyncIOMotorClient(MONGODB_URI)
db = client['root']  # Use your MongoDB database

# Financing options sample data
financing_options_data = [
    {
        "option_name": "Standard Loan",
        "interest_rate": 5.5,
        "duration_months": 24,
        "max_amount": 100000,
        "description": "A standard loan with fixed interest rate.",
        "eligibility_criteria": {
            "min_income": 30000,
            "credit_score": 650
        }
    },
    {
        "option_name": "Home Loan",
        "interest_rate": 3.2,
        "duration_months": 360,
        "max_amount": 500000,
        "description": "A home loan with lower interest rate for purchasing homes.",
        "eligibility_criteria": {
            "min_income": 50000,
            "credit_score": 700
        }
    },
    {
        "option_name": "Auto Loan",
        "interest_rate": 4.1,
        "duration_months": 60,
        "max_amount": 30000,
        "description": "A loan designed for purchasing vehicles.",
        "eligibility_criteria": {
            "min_income": 25000,
            "credit_score": 600
        }
    }
]

# Function to insert sample data into financing_options collection
async def populate_financing_options():
    try:
        logger.info("Populating financing_options collection with sample data...")
        await db['financing_options'].insert_many(financing_options_data)
        logger.info("Successfully populated financing_options collection.")
    except Exception as e:
        logger.error(f"Error occurred while populating financing_options collection: {e}")

# Run the populate function
if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(populate_financing_options())
    loop.close()
