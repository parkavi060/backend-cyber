from pymongo import ASCENDING, DESCENDING

def init_db_indexes(db, logger):
    """
    Initializes indexes for MongoDB collections to improve query performance and scalability.
    """
    try:
        # Users Collection Indexes
        db.users.create_index([("username", ASCENDING)], unique=True)
        
        # Incidents Collection Indexes
        db.incidents.create_index([("reported_by", ASCENDING)])
        db.incidents.create_index([("status", ASCENDING)])
        db.incidents.create_index([("risk_level", ASCENDING)])
        db.incidents.create_index([("created_at", DESCENDING)])
        db.incidents.create_index([("analyst_reviewed", ASCENDING)])
        
        logger.info("MongoDB indexes initialized successfully.")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize MongoDB indexes: {e}")
        return False
