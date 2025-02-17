from password_validator import PasswordValidator

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