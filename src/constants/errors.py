# Token Errors
TOKEN_EXPIRED = "The token has expired."
TOKEN_NOT_FRESH = "The token is not fresh. Please use a fresh token."
INVALID_TOKEN = "Invalid token. Signature verification failed."
TOKEN_REVOKED = "The token has been revoked."
MISSING_TOKEN = "Request does not contain an access token."


# Authentication Errors
USER_NOT_FOUND = "User not found."
USER_ALREADY_EXISTS = "A user with that username already exists."
USER_ALREADY_ACTIVATED = "User is already activated."
INVALID_CREDENTIALS = "Invalid credentials."
ACCOUNT_NOT_ACTIVATED = "Account is not activated."

# Password Change Error
INCORRECT_OLD_PASSWORD = "Incorrect old password."

# Validation Errors
VALIDATION_ERROR = "Validation Error"
MISSING_FIELD_ERROR = "Missing required field: {}."
NON_NULL_ERROR = "Field cannot be null: {}."
INVALID_FORMAT = "Invalid format for field {}. Expected a valid {}."
INVALID_OR_EXPIRED_TOKEN = "Invalid or expired token."

# General Errors
INTERNAL_SERVER_ERROR = "An unexpected error occurred. Please try again later."
BAD_REQUEST = "Invalid request parameters."
PERMISSION_DENIED = "Permission denied. Missing required roles."
NO_DEFAULT_ROLE = "Internal error: No default role assigned."