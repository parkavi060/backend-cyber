from flask import Flask
from app.config import Config
from app.extensions import jwt
from pymongo import MongoClient
from app.routes.admin_routes import admin_bp
from app.extensions import db

from flask_cors import CORS

def create_app():

    app = Flask(__name__)
    CORS(app) # Allow cross-origin requests
    app.config.from_object(Config)
    app.register_blueprint(admin_bp, url_prefix="/admin")

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

        print("\n✅ MongoDB CONNECTED SUCCESSFULLY\n")

    except Exception as e:
        print("\n❌ MongoDB CONNECTION FAILED\n")
        print(e)

    # ✅ Register Blueprints AFTER DB
    from app.routes.auth_routes import auth_bp
    from app.routes.incident_routes import incident_bp
    from app.routes.test_routes import test_bp

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(incident_bp, url_prefix="/incident")
    app.register_blueprint(test_bp)

    return app
