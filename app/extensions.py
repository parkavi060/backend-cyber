from flask_jwt_extended import JWTManager
from pymongo import MongoClient

jwt = JWTManager()

mongo = None
db = None
