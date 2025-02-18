from flask import jsonify
from werkzeug.exceptions import HTTPException, UnprocessableEntity
from marshmallow.exceptions import ValidationError
from src.modules.auth.services import is_token_blacklisted

def register_error_handlers(app):

    @app.errorhandler(UnprocessableEntity)
    def handle_validation_error(e):
        """Handles Marshmallow validation errors (422 Unprocessable Entity)."""

        validation_messages = getattr(e, "data", {}).get("messages", e.description)

        return jsonify({
            "error": "Validation Error",
            "message": validation_messages,  
            "status_code": 422
        }), 422
    
    @app.errorhandler(HTTPException)
    def handle_http_exception(e):
        """Handles standard HTTP exceptions like 404, 401, etc."""
        response = e.get_response()
        
        message = getattr(e, "data", {}).get("message", e.description)  

        response.data = jsonify({
            "error": e.name,
            "message": message,
            "status_code": e.code
        }).data
        response.content_type = "application/json"
        return response, e.code
    
    @app.errorhandler(Exception)
    def handle_generic_exception(e):
        """Handles all uncaught exceptions."""
        return jsonify({
            "error": "Internal Server Error",
            "message": "An unexpected error occurred."
        }), 500


    @app.errorhandler(KeyError)
    def handle_key_error(error):
        """Handles KeyError when a required JSON field is missing."""
        response = jsonify({
            "error": "Bad Request",
            "message": f"Missing required field: {str(error)}",
            "status_code": 400
        })
        response.status_code = 400
        return response


def register_jwt_handlers(jwt):
    """Registers all JWT-related error handlers using the initialized JWTManager instance."""

    @jwt.token_in_blocklist_loader
    def check_if_token_in_blocklist(jwt_header, jwt_payload):
        """Checks if a JWT token is revoked (blacklisted)."""
        return is_token_blacklisted(jwt_payload["jti"])

    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        """Handles revoked tokens."""
        return jsonify({
            "error": "Unauthorized",
            "message": "The token has been revoked.",
            "status_code": 401
        }), 401

    @jwt.needs_fresh_token_loader
    def token_not_fresh_callback(jwt_header, jwt_payload):
        """Handles requests where a fresh token is required."""
        return jsonify({
            "error": "Unauthorized",
            "message": "The token is not fresh. Please use a fresh token.",
            "status_code": 401
        }), 401

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        """Handles expired tokens."""
        return jsonify({
            "error": "Unauthorized",
            "message": "The token has expired.",
            "status_code": 401
        }), 401

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        """Handles invalid tokens (wrong signature, tampered, etc.)."""
        return jsonify({
            "error": "Unauthorized",
            "message": "Invalid token. Signature verification failed.",
            "status_code": 401
        }), 401

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        """Handles missing access tokens."""
        return jsonify({
            "error": "Unauthorized",
            "message": "Request does not contain an access token.",
            "status_code": 401
        }), 401