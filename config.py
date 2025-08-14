import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    MONGO_URI = os.getenv('MONGO_URI','mongodb://localhost:27017')
    MONGO_DB = os.getenv('MONGO_DB','threatfox')
    MONGO_COLLECTION = os.getenv('MONGO_COLLECTION','icos') 