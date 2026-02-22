"""
User Model Definition
"""

class UserModel:
    """
    Schema for User document in MongoDB
    - username: Unique identifier (serviceId)
    - password: Hashed password
    - role: user | admin | analyst | cert_analyst
    - created_at: Timestamp
    """
    COLLECTION = "users"
