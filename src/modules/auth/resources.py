from flask.views import MethodView
from flask_smorest import Blueprint, abort
from flask import current_app, request, jsonify

from src.extensions import db
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from src.modules.auth.schemas import UserSchema, UserRegisterSchema, ChangePasswordSchema, ResetPasswordSchema, SendEmailSchema
from src.modules.auth.models import RoleModel, UserModel

from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt_identity, jwt_required, get_jwt
from src.modules.auth.services import validate_password, verify_token, send_activation_email, send_password_reset_email, add_token_to_blacklist, verify_password
from http import HTTPStatus
from src.constants.messages import *

blp = Blueprint("auth", __name__, description="Authentication and User Management")

@blp.route("/login")
class UserLogin(MethodView):
    @blp.arguments(UserSchema)
    def post(self, user_data):
        stm = select(UserModel).where(UserModel.username == user_data["username"])
        user = db.session.execute(stm).scalars().first()

        current_app.logger.info(f"Login attempt for username: {user_data['username']}")

        if not user:
            current_app.logger.warning(f"User '{user_data['username']}' not found.")
            abort(HTTPStatus.UNAUTHORIZED, message=INVALID_CREDENTIALS)

        if not user.is_active:
            abort(HTTPStatus.UNAUTHORIZED, message=ACCOUNT_NOT_ACTIVATED)

        if verify_password(user_data["password"], user._password):
            if not isinstance(user.id, int):
                abort(HTTPStatus.INTERNAL_SERVER_ERROR, message="Invalid user ID format")

            user_id = str(user.id)
            current_app.logger.info(f"Login successful for user: {user.username}")

            access_token = create_access_token(
                identity=user_id, 
                fresh=True,
                additional_claims={"roles": [role.name for role in user.roles]}
            )
            refresh_token = create_refresh_token(identity=user_id)

            return {"access_token": access_token, "refresh_token": refresh_token}
        
        current_app.logger.warning(f"Login failed for username: {user_data['username']}")
        abort(HTTPStatus.UNAUTHORIZED, message=INVALID_CREDENTIALS)

@blp.route("/refresh")
class TokenRefresh(MethodView):
    @jwt_required(refresh=True)
    def post(self):
        current_user_id = get_jwt_identity()
        user = db.session.get(UserModel, current_user_id)

        if not user:
            abort(HTTPStatus.NOT_FOUND, message=USER_NOT_FOUND)

        roles = [role.name for role in user.roles]

        new_token = create_access_token(
            identity=current_user_id,
            fresh=False,
            additional_claims={"roles": roles}
        )
        return {"access_token": new_token}
    
@blp.route("/register")
class UserRegister(MethodView):
    @blp.arguments(UserRegisterSchema)
    @blp.response(HTTPStatus.CREATED, UserRegisterSchema)
    def post(self, user_data):
        current_app.logger.info(f"User registration attempt: {user_data['username']}")

        default_role = db.session.execute(
            select(RoleModel).where(RoleModel.default == True).limit(1)
        ).scalars().first()

        if not default_role:
            current_app.logger.error("No default role found in database.")
            abort(HTTPStatus.INTERNAL_SERVER_ERROR, message=NO_DEFAULT_ROLE)

        try:
            validate_password(user_data["password"])
        except ValueError as e:
            abort(HTTPStatus.BAD_REQUEST, message=str(e))

        user = UserModel(username=user_data["username"], email=user_data["email"], is_active=False)
        user.password = user_data["password"]
        user.roles.append(default_role)

        try:
            db.session.add(user)
            db.session.commit()
            current_app.logger.info(f"User created successfully: {user.username}")

            send_activation_email(user.email)

            return user 

        except IntegrityError:
            db.session.rollback()
            current_app.logger.warning(f"Registration failed: Username '{user_data['username']}' already exists")
            abort(HTTPStatus.CONFLICT, message=USER_ALREADY_EXISTS)

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Database error during registration: {str(e)}")
            abort(HTTPStatus.INTERNAL_SERVER_ERROR, message=INTERNAL_SERVER_ERROR)


@blp.route("/activation/<string:token>")
class UserActivateAccount(MethodView):
    def get(self, token):
        email = verify_token(token)
        if email:
            stm = select(UserModel).where(UserModel.email == email)
            user = db.session.execute(stm).scalars().first()
            if user:
                user.is_active = True  
                db.session.commit()
                current_app.logger.info(USER_ACTIVATED.format(email))
                return jsonify({"message": USER_ACTIVATED.format(email)}), HTTPStatus.OK
            
            abort(HTTPStatus.NOT_FOUND, message=USER_NOT_FOUND)
        abort(HTTPStatus.BAD_REQUEST, message=INVALID_OR_EXPIRED_TOKEN)

@blp.route("/resend_activation")
class UserResendActivateAccount(MethodView):
    @blp.arguments(SendEmailSchema)
    def post(self, user_data):
        stm = select(UserModel).where(UserModel.email == user_data["email"])
        user = db.session.execute(stm).scalars().first()

        if not user:
            abort(HTTPStatus.NOT_FOUND, message=USER_NOT_FOUND)

        if user.is_active:
            abort(HTTPStatus.CONFLICT, message=USER_ALREADY_ACTIVATED)

        try:
            send_activation_email(user.email)
            current_app.logger.info(f"Activation email resent to: {user.email}")
            return jsonify({"message": ACTIVATION_EMAIL_RESENT}), HTTPStatus.OK
        except Exception as e:
            current_app.logger.error(f"Error resending activation email: {str(e)}")
            abort(HTTPStatus.INTERNAL_SERVER_ERROR, message=INTERNAL_SERVER_ERROR)

@blp.route("/change_password")
class ChangePassword(MethodView):
    """Allows an authenticated user to change their password."""

    @jwt_required(fresh=True)
    @blp.arguments(ChangePasswordSchema)
    def post(self, user_data):
        """Change the user's password."""
        user_id = get_jwt_identity()  # Get user ID from JWT token
        current_app.logger.info(f"Password change attempt")

        old_password = user_data["old_password"]
        new_password = user_data["new_password"]

        try:
            validate_password(new_password)
        except ValueError as e:
            abort(HTTPStatus.BAD_REQUEST, message=str(e))

        user = db.session.get(UserModel, user_id)

        if not user:
            abort(HTTPStatus.NOT_FOUND, message=USER_NOT_FOUND)

        if not verify_password(old_password, user._password):
            abort(HTTPStatus.UNAUTHORIZED, message=INCORRECT_OLD_PASSWORD)

        user.password = new_password 
        db.session.commit()

        current_app.logger.info(f"User {user.username} changed their password.")

        return jsonify({"message": PASSWORD_CHANGED_SUCCESS}), HTTPStatus.OK


@blp.route("/forgot_password")
class ForgotPassword(MethodView):
    """Allows users to request a password reset token."""

    @blp.arguments(SendEmailSchema)
    def post(self, user_data):
        """Return a password reset token for API-based reset."""
        stm = select(UserModel).where(UserModel.email == user_data["email"])
        user = db.session.execute(stm).scalars().first()

        if not user:
            abort(HTTPStatus.NOT_FOUND, message=USER_NOT_FOUND)

        # Send the reset email
        try:
            send_password_reset_email(user.email)
        except RuntimeError as e:
            abort(HTTPStatus.INTERNAL_SERVER_ERROR, message=INTERNAL_SERVER_ERROR)

        return jsonify({"message": PASSWORD_RESET_EMAIL_SENT}), HTTPStatus.OK

@blp.route("/reset-password/<string:reset_token>")
class ResetPassword(MethodView):
    """Allows users to reset their password using a token."""

    @blp.arguments(ResetPasswordSchema)
    def post(self, user_data, reset_token):
        """Reset the user's password using a valid token."""
        new_password = user_data["new_password"]

        email = verify_token(reset_token)
        if not email:
            abort(HTTPStatus.BAD_REQUEST, message=INVALID_OR_EXPIRED_TOKEN)

        stm = select(UserModel).where(UserModel.email == email)
        user = db.session.execute(stm).scalars().first()        
        if not user:
            abort(HTTPStatus.NOT_FOUND, message=USER_NOT_FOUND)

        try:
            validate_password(new_password)
        except ValueError as e:
            abort(HTTPStatus.BAD_REQUEST, message=str(e))

        user.password = new_password 
        db.session.commit()

        return jsonify({"message": PASSWORD_RESET_SUCCESS}), HTTPStatus.OK
    
@blp.route("/logout")
class Logout(MethodView):
    """Logs out a user by revoking their token."""
    @jwt_required(refresh=True)
    def post(self):
        add_token_to_blacklist()
        return jsonify({"message": LOGOUT_SUCCESS}), HTTPStatus.OK