class AuthRoles:
    USER = "user"
    ADMIN = "admin"
    ANALYST = "analyst"
    CERT_ANALYST = "cert_analyst"

    VALID_ROLES = [USER, ADMIN, ANALYST, CERT_ANALYST]

class AuthMessages:
    INVALID_CREDENTIALS = "Invalid credentials"
    USER_ALREADY_EXISTS = "User already exists"
    REGISTER_SUCCESS = "Registered successfully"
    LOGIN_SUCCESS = "Login successful"
    LOGOUT_SUCCESS = "Logged out successfully"
    WELCOME_PROTECTED = "Welcome {}, you accessed a protected route!"
    USERNAME_REQUIRED = "Username is required"
    PASSWORD_REQUIRED = "Password is required"
    INVALID_ROLE = "Invalid role provided"
