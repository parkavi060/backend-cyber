import requests
import uuid

BASE_URL = "http://127.0.0.1:5000/api/auth"

def test_auth():
    # Generate a unique serviceId for registration
    service_id = f"test_user_{uuid.uuid4().hex[:8]}"
    password = "testpassword123"

    print(f"\n--- Testing Authentication Fixes ---")

    # 1. Test Registration (201)
    print(f"\n[1] Testing Registration for {service_id}...")
    reg_response = requests.post(f"{BASE_URL}/register", json={
        "serviceId": service_id,
        "password": password
    })
    print(f"Status: {reg_response.status_code}")
    print(f"Body: {reg_response.json()}")

    # 2. Test Login (200)
    print(f"\n[2] Testing Login for {service_id}...")
    login_response = requests.post(f"{BASE_URL}/login", json={
        "serviceId": service_id,
        "password": password
    })
    print(f"Status: {login_response.status_code}")
    print(f"Body: {login_response.json()}")

    # 3. Test Login with Missing serviceId (400)
    print(f"\n[3] Testing Login with Missing serviceId (400 Expected)...")
    missing_service_id = requests.post(f"{BASE_URL}/login", json={
        "password": password
    })
    print(f"Status: {missing_service_id.status_code}")
    print(f"Body: {missing_service_id.json()}")

    # 4. Test Login with Missing password (400)
    print(f"\n[4] Testing Login with Missing password (400 Expected)...")
    missing_password = requests.post(f"{BASE_URL}/login", json={
        "serviceId": service_id
    })
    print(f"Status: {missing_password.status_code}")
    print(f"Body: {missing_password.json()}")

if __name__ == "__main__":
    try:
        test_auth()
    except Exception as e:
        print(f"❌ Error: {e}")
