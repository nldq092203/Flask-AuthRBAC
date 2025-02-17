from flask import jsonify
from werkzeug.exceptions import HTTPException

def register_error_handlers(app):

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