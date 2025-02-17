from password_validator import PasswordValidator
from itsdangerous import URLSafeTimedSerializer
from flask import current_app
from flask_mail import Mail, Message
from werkzeug.exceptions import InternalServerError

password_schema = PasswordValidator()
password_schema \
    .min(8) \
    .max(128) \
    .has().uppercase() \
    .has().lowercase() \
    .has().digits() \
    .has().symbols() \

def validate_password(password):
    if not password_schema.validate(password):
        raise ValueError("Password must be 8-128 characters long, contain uppercase, lowercase, a digit and a symbol.")
    

mail = Mail()

def generate_activation_token(email):
    """Generate a secure activation token."""
    serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
    return serializer.dumps(email, salt=current_app.config["SECURITY_PASSWORD_SALT"])

def verify_activation_token(token, expiration=3600):
    """Verify and decode an activation token."""
    serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
    try:
        email = serializer.loads(token, salt=current_app.config["SECURITY_PASSWORD_SALT"], max_age=expiration)
        return email
    except Exception:
        return None


def send_activation_email(user_email):
    """Send an account activation email."""
    activation_token = generate_activation_token(user_email)
    
    # Direct backend API endpoint for activation
    activation_link = f"http://127.0.0.1:5000/api/auth/activation/{activation_token}"

    msg = Message(
        subject="Activate Your Account",
        sender="noreply@example.com",
        recipients=[user_email],
        body=f"Click the following link to activate your account via the backend API: {activation_link}"
    )

    try:
        mail.send(msg)
    except Exception as e:
        raise InternalServerError(f"Failed to send activation email: {str(e)}")