from flask.views import MethodView
from flask_smorest import Blueprint, abort
from passlib.hash import pbkdf2_sha256
from flask import current_app, request, jsonify

from src.extensions.database import db
from sqlalchemy import select
from src.models.user import UserModel
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from src.modules.auth.schemas import UserSchema, UserRegisterSchema, ChangePasswordSchema, ResetPasswordSchema, SendEmailSchema
from src.modules.auth.models import RoleModel

from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt_identity, jwt_required, get_jwt
from src.modules.auth.services import validate_password, verify_token, send_activation_email, send_password_reset_email, add_token_to_blacklist
from src.common.decorators import role_required

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
            abort(401, message="Invalid credentials")

        if not user.is_active:
            abort(401, message="Account is not activated.")

        if user.verify_password(user_data["password"]): 
            # Ensure user.id is a valid integer
            if not isinstance(user.id, int):
                abort(500, message="Invalid user ID format")

            # Convert user.id to a string
            user_id = str(user.id)
            current_app.logger.info(f"Login successful for user: {user.username}")

            # Create a JWT access token
            access_token = create_access_token(
                identity=user_id, 
                fresh=True,
                additional_claims={"roles":[role.name for role in user.roles]}
                )
            # Create a refresh token
            refresh_token = create_refresh_token(identity=user_id)

            return {"access_token": access_token, "refresh_token": refresh_token}
        current_app.logger.warning(f"Login failed for username: {user_data['username']}")
        abort(401, message="Invalid credentials")

@blp.route("/refresh")
class TokenRefresh(MethodView):
    @jwt_required(refresh=True)
    def post(self):
        current_user_id = get_jwt_identity()
        user = db.session.get(UserModel, current_user_id)

        if not user:
            abort(401, message="User not found")

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
    @blp.response(201, UserRegisterSchema)
    def post(self, user_data):
        current_app.logger.info(f"User registration attempt: {user_data['username']}")

        default_role = db.session.execute(
            select(RoleModel).where(RoleModel.default == True).limit(1)
        ).scalars().first()

        if not default_role:
            current_app.logger.error("No default role found in database.")
            abort(500, message="Internal error: No default role assigned.")

        # Validate password format
        try:
            validate_password(user_data["password"])
        except ValueError as e:
            abort(400, message=str(e))        

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
            abort(409, message="A user with that username already exists.")

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Database error during registration: {str(e)}")
            abort(500, message="An internal server error occurred. Please try again later.")
        


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
                current_app.logger.error(f"Account for {email} activated successfully!")
                return jsonify({"message": f"Account for {email} activated successfully!"}), 200
            abort(404, message="User not found.")
        abort(400, message="Invalid or expired token.")

@blp.route("/resend_activation")
class UserResendActivateAccount(MethodView):
    @blp.arguments(SendEmailSchema)
    def post(self, user_data):
        """Resends an activation email if the user exists and is not already activated."""

        stm = select(UserModel).where(UserModel.email == user_data["email"])
        user = db.session.execute(stm).scalars().first()

        if not user:
            abort(404, message="User not found.")

        if user.is_active:
            abort(409, message="User is already activated.")

        try:
            send_activation_email(user.email)
            current_app.logger.info(f"Activation email resent to: {user.email}")
            return jsonify({"message": "Activation email resent successfully."}), 200
        except Exception as e:
            current_app.logger.error(f"Error resending activation email to {user.email}: {str(e)}")
            abort(500, message="An error occurred while resending the activation email. Please try again later.")


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

        # Validate password format
        try:
            validate_password(new_password)
        except ValueError as e:
            abort(400, message=str(e))        

        user = db.session.get(UserModel, user_id)

        if not user:
            abort(404, message="User not found.")

        # Check if old password is correct
        if not user.verify_password(old_password):
            abort(401, message="Incorrect old password.")

        # Validate new password strength
        try:
            validate_password(new_password)
        except ValueError as e:
            abort(400, message=str(e))

        # Update password securely
        user.password = new_password 
        db.session.commit()

        current_app.logger.info(f"User {user.username} changed their password.")

        return jsonify({"message": "Password changed successfully."}), 200

@blp.route("/forgot_password")
class ForgotPassword(MethodView):
    """Allows users to request a password reset token."""

    @blp.arguments(SendEmailSchema)
    def post(self, user_data):
        """Return a password reset token for API-based reset."""
        stm = select(UserModel).where(UserModel.email == user_data["email"])
        user = db.session.execute(stm).scalars().first()

        if not user:
            abort(404, message="User not found.")

        # Send the reset email
        try:
            send_password_reset_email(user.email)
        except RuntimeError as e:
            abort(500, message=str(e))

        return jsonify({"message": "Password reset email sent successfully."}), 200

@blp.route("/reset-password/<string:reset_token>")
class ResetPassword(MethodView):
    """Allows users to reset their password using a token."""

    @blp.arguments(ResetPasswordSchema)
    def post(self, user_data, reset_token):
        """Reset the user's password using a valid token."""
        new_password = user_data["new_password"]

        # Verify the reset token
        email = verify_token(reset_token)
        if not email:
            abort(400, message="Invalid or expired token.")


        stm = select(UserModel).where(UserModel.email == email)
        user = db.session.execute(stm).scalars().first()        
        if not user:
            abort(404, message="User not found.")

        # Validate password strength
        try:
            validate_password(new_password)
        except ValueError as e:
            abort(400, message=str(e))

        # Update password securely
        user.password = new_password 
        db.session.commit()

        return jsonify({"message": "Password reset successfully."}), 200
    

@blp.route("/logout")
class Logout(MethodView):
    """Logs out a user by revoking their token."""

    @jwt_required(refresh=True)
    def post(self):
        add_token_to_blacklist()
        return jsonify({"message": "Successfully logged out."}), 200