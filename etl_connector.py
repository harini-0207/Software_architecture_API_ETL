import requests
import json
from datetime import datetime
import re
import time
from pymongo import MongoClient, UpdateOne
from config import Config

# ======================
# VALIDATION FUNCTIONS
# ======================

def validate_response(response):
    """Check API response for errors/empty data"""
    if response.status_code != 200:
        raise ValueError(f"API returned {response.status_code}: {response.text}")
    
    try:
        data = response.json()
        if not data:
            raise ValueError("Empty API response")
        return data
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON response")

def validate_ioc(ioc):
    """Validate individual IOC fields"""
    required_fields = ['ioc_value', 'ioc_type', 'malware']
    for field in required_fields:
        if field not in ioc:
            raise ValueError(f"Missing required field: {field} in IOC {ioc.get('id')}")

    if not isinstance(ioc['ioc_value'], str) or not ioc['ioc_value'].strip():
        raise ValueError(f"Invalid indicator value: {ioc['ioc_value']}")

    # Additional validation rules
    if ioc['ioc_type'] == 'domain' and '.' not in ioc['ioc_value']:
        raise ValueError(f"Invalid domain format: {ioc['ioc_value']}")
    if 'confidence_level' in ioc and not (0 <= ioc['confidence_level'] <= 100):
        raise ValueError(f"Invalid confidence level: {ioc['confidence_level']}")

# ======================
# CORE ETL FUNCTIONS
# ======================

def extract_data():
    """Extract data from ThreatFox JSON feed with validation"""
    url = "https://threatfox.abuse.ch/export/json/recent/"
    headers = {
        "User-Agent": "ThreatFox-ETL-Connector/1.0",
        "Accept": "application/json"
    }
    
    try:
        # Rate limiting
        time.sleep(2)
        
        response = requests.get(url, headers=headers, timeout=30)
        data = validate_response(response)
        
        iocs = []
        for key, items in data.items():
            if isinstance(items, list):
                for ioc in items:
                    try:
                        validate_ioc(ioc)
                        iocs.append(ioc)
                    except ValueError as e:
                        print(f"⚠️ Skipping invalid IOC: {str(e)}")
                        continue
        
        print(f"✅ Extracted {len(iocs)} valid IOCs")
        return iocs
        
    except Exception as e:
        print(f"❌ Extraction failed: {str(e)}")
        return []

def parse_datetime(dt_str):
    """Parse datetime string into datetime object"""
    if not dt_str:
        return None
    try:
        return datetime.strptime(dt_str, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        print(f"⚠️ Could not parse timestamp: {dt_str}")
        return None

def transform_data(raw_data):
    """Transform raw data for MongoDB with validation"""
    transformed = []
    for item in raw_data:
        try:
            doc = {
                'ioc_id': item.get('id'),
                'indicator': item['ioc_value'],
                'ioc_type': item['ioc_type'],
                'threat_type': item.get('threat_type'),
                'malware': item['malware'],
                'malware_alias': item.get('malware_alias', []),
                'first_seen': parse_datetime(item.get('first_seen_utc')),
                'last_seen': parse_datetime(item.get('last_seen_utc')),
                'confidence_level': min(max(item.get('confidence_level', 50), 0), 100),
                'reference': item.get('reference', []),
                'tags': item.get('tags', []),
                'etl_timestamp': datetime.utcnow()
            }
            # Clean empty values
            transformed.append({k: v for k, v in doc.items() if v not in (None, [])})
        except Exception as e:
            print(f"⚠️ Transformation failed for item {item.get('id')}: {str(e)}")
            continue
    
    return transformed

def verify_mongodb_insert(collection, expected_count):
    """Verify documents were inserted correctly"""
    actual_count = collection.count_documents({})
    if actual_count < expected_count:
        raise ValueError(f"Data loss! Expected {expected_count}, found {actual_count}")
    print(f"✅ MongoDB verification: {actual_count} records")

def load_data(transformed_data):
    """Load data into MongoDB with validation"""
    if not transformed_data:
        print("⚠️ No data to load")
        return False
    
    try:
        client = MongoClient(Config.MONGO_URI)
        db = client[Config.MONGO_DB]
        collection = db[Config.MONGO_COLLECTION]
        
        # Get initial count
        initial_count = collection.count_documents({})
        
        # Create indexes if missing
        indexes = {
            'indicator_1': [('indicator', 1)],
            'ioc_type_1': [('ioc_type', 1)],
            'malware_1': [('malware', 1)]
        }
        
        for name, fields in indexes.items():
            if name not in collection.index_information():
                collection.create_index(fields, name=name)
        
        # Bulk upsert
        operations = [
            UpdateOne(
                {'indicator': doc['indicator']},
                {'$set': doc},
                upsert=True
            ) for doc in transformed_data
        ]
        
        result = collection.bulk_write(operations)
        print(f"📊 Processed {len(operations)} records. "
              f"Inserted: {result.upserted_count}, "
              f"Updated: {result.modified_count}")
        
        # Verify insertion
        verify_mongodb_insert(collection, initial_count + result.upserted_count)
        return True
        
    except Exception as e:
        print(f"❌ Loading failed: {str(e)}")
        return False
    finally:
        client.close()

# ======================
# MAIN EXECUTION
# ======================

def run_etl():
    """Orchestrate the ETL pipeline with validation"""
    print("\n" + "="*50)
    print("🚀 Starting ThreatFox ETL Pipeline")
    print("="*50)
    
    try:
        # Extract
        print("\n🔍 Extracting data...")
        raw_data = extract_data()
        if not raw_data:
            return False
        
        # Transform
        print("\n🔄 Transforming data...")
        transformed_data = transform_data(raw_data)
        if not transformed_data:
            return False
        
        # Load
        print("\n📂 Loading to MongoDB...")
        success = load_data(transformed_data)
        
        if success:
            print("\n" + "="*50)
            print("🎉 ETL completed successfully!")
            print("="*50)
        return success
        
    except Exception as e:
        print(f"\n❌ Critical ETL failure: {str(e)}")
        return False

if __name__ == "__main__":
    run_etl()