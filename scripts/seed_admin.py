import os
import sys
from pymongo import MongoClient
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv
from datetime import datetime

# Add parent directory to path to import constants if needed
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def seed_admin():
    # Load environment variables
    load_dotenv()
    
    mongo_uri = os.getenv("MONGO_URI")
    if not mongo_uri:
        print("❌ Error: MONGO_URI not found in .env file")
        return

    try:
        # Connect to MongoDB
        client = MongoClient(mongo_uri)
        db = client["cyberguard"]
        
        print("\n--- Staff User Seeding Script ---")
        username = input("Enter Staff Service ID (Username): ").strip()
        password = input("Enter Staff Password: ").strip()
        
        print("\nSelect Role:")
        print("1. Admin")
        print("2. Analyst")
        role_choice = input("Choice (1/2): ").strip()
        
        role = "admin" if role_choice == "1" else "analyst"

        if not username or not password:
            print("❌ Error: Username and password are required")
            return

        # Check if user already exists
        if db.users.find_one({"username": username}):
            print(f"⚠️ User '{username}' already exists")
            confirm = input("Overwrite existing user? (y/n): ").lower()
            if confirm != 'y':
                print("Operation cancelled")
                return
            db.users.delete_one({"username": username})

        # Hash password and insert
        hashed_password = generate_password_hash(password)
        db.users.insert_one({
            "username": username,
            "password": hashed_password,
            "role": role,
            "created_at": datetime.utcnow()
        })

        print(f"\n✅ {role.capitalize()} user '{username}' added successfully!")
        
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    seed_admin()
