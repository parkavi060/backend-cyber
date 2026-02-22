from flask import Flask
from app.config import Config
from app.extensions import jwt
import nltk
from pymongo import MongoClient
from app.routes.admin_routes import admin_bp
from app.extensions import db

from flask_cors import CORS
from app.utils.logger import setup_logger
from app.utils.error_handler import register_error_handlers
from app.utils.db_init import init_db_indexes

def create_app():

    app = Flask(__name__)
    CORS(app) # Allow cross-origin requests
    app.config.from_object(Config)

    # ✅ Download NLTK data
    try:
        nltk.download('vader_lexicon', quiet=True)
    except Exception as e:
        app.logger.warning(f"Failed to download NLTK data: {e}")
    
    # ✅ Setup Logging & Error Handling
    setup_logger(app)
    register_error_handlers(app)
    
    app.register_blueprint(admin_bp, url_prefix="/api/admin")

    # ✅ Initialize JWT
    jwt.init_app(app)

    # ✅ Mongo Connection FIRST
    try:
        client = MongoClient(
            app.config["MONGO_URI"],
            serverSelectionTimeoutMS=5000
        )

        client.server_info()

        # attach db globally
        app.db = client["cyberguard"]
        
        # ✅ Initialize Indexes
        init_db_indexes(app.db, app.logger)

        app.logger.info("MongoDB CONNECTED SUCCESSFULLY")

    except Exception as e:
        app.logger.error(f"MongoDB CONNECTION FAILED: {e}")

    # ✅ Register Blueprints AFTER DB
    from app.routes.auth_routes import auth_bp
    from app.routes.incident_routes import incident_bp
    from app.routes.test_routes import test_bp

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(incident_bp, url_prefix="/incident")
    app.register_blueprint(test_bp)

    return app
