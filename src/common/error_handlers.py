from werkzeug.exceptions import HTTPException, UnprocessableEntity
from marshmallow.exceptions import ValidationError
from src.modules.auth.services import is_token_blacklisted
from src.constants.messages import *
from src.constants.errors import *
from src.common.response_builder import ResponseBuilder
from flask_limiter.errors import RateLimitExceeded
def register_error_handlers(app):
    @app.errorhandler(UnprocessableEntity)
    def handle_validation_error(e):
        """Handles Marshmallow validation errors (422 Unprocessable Entity)."""
        validation_messages = getattr(e, "data", {}).get("messages", e.description)
        return ResponseBuilder().error(
                error=VALIDATION_ERROR,
                message=validation_messages,
                status_code=422
            ).build()
    
    @app.errorhandler(HTTPException)
    def handle_http_exception(e):
        """Handles standard HTTP exceptions like 404, 401, etc."""
        error_name = e.name or "HTTPException"
        status_code = e.code or 500
        message = getattr(e, "data", {}).get("message", e.description)

        return ResponseBuilder().error(
            error=error_name,
            message=message,
            status_code=status_code
        ).build()

        
    
    @app.errorhandler(Exception)
    def handle_generic_exception(e):
        """Handles all uncaught exceptions."""
        return ResponseBuilder().error(
            error="Internal Server Error",
            message=INTERNAL_SERVER_ERROR,
            status_code=500
        ).build()

    @app.errorhandler(KeyError)
    def handle_key_error(error):
        """Handles KeyError when a required JSON field is missing."""
        return ResponseBuilder().error(
            error="Bad Request",
            message=MISSING_FIELD_ERROR.format(str(error)),
            status_code=400
        ).build()


def register_jwt_handlers(jwt):
    """Registers all JWT-related error handlers using the initialized JWTManager instance."""

    @jwt.token_in_blocklist_loader
    def check_if_token_in_blocklist(jwt_header, jwt_payload):
        """Checks if a JWT token is revoked (blacklisted)."""
        return is_token_blacklisted(jwt_payload["jti"])

    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        """Handles revoked tokens."""
        return ResponseBuilder().error(
            error="Unauthorized",
            message=TOKEN_REVOKED,
            status_code=401
        ).build

    @jwt.needs_fresh_token_loader
    def token_not_fresh_callback(jwt_header, jwt_payload):
        """Handles requests where a fresh token is required."""
        return ResponseBuilder().error(
            error="Unauthorized",
            message=TOKEN_NOT_FRESH,
            status_code=401
        ).build()

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        """Handles expired tokens."""
        return ResponseBuilder().error(
            error="Unauthorized",
            message=TOKEN_EXPIRED,
            status_code=401
        ).build()

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        """Handles invalid tokens (wrong signature, tampered, etc.)."""
        return ResponseBuilder().error(
            error="Unauthorized",
            message=INVALID_TOKEN,
            status_code=401
        )

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        """Handles missing access tokens."""
        return ResponseBuilder().error(
            error="Unauthorized",
            message=MISSING_TOKEN,
            status_code=401
        )

def register_limiter_handlers(limiter):
    def rate_limit_error_handler(error: RateLimitExceeded):
        return ResponseBuilder().error(
            error="Too Many Requests",
            message=TOO_MANY_REQUEST,
            status_code=429
        )

    limiter.on_error = rate_limit_error_handler