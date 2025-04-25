import uvicorn
import logging
from init_db import init_db

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

if __name__ == "__main__":
    # Initialize the database
    logger.info("Initializing database...")
    init_db()
    
    # Start the FastAPI server
    logger.info("Starting FastAPI server...")
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
