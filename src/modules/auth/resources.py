from flask.views import MethodView
from flask_smorest import Blueprint, abort
from passlib.hash import pbkdf2_sha256
from flask import current_app

from src.extensions.database import db
from sqlalchemy import select
from src.models.user import UserModel
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from src.modules.auth.schemas import UserSchema
from src.modules.auth.models import RoleModel

from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt_identity, jwt_required, get_jwt
from src.common.utils import validate_password

blp = Blueprint("Users", "users", description="Operations on users")

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
            access_token = create_access_token(identity=user_id, fresh=True)
            # Create a refresh token
            refresh_token = create_refresh_token(identity=user_id)

            return {"access_token": access_token, "refresh_token": refresh_token}
        current_app.logger.warning(f"Login failed for username: {user_data['username']}")
        abort(401, message="Invalid credentials")

@blp.route("/refresh")
class TokenRefresh(MethodView):
    @jwt_required(refresh=True)
    def post(self):
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user, fresh=False)
        return {"access_token": new_token}

@blp.route("/register")
class UserRegister(MethodView):
    @blp.arguments(UserSchema)
    @blp.response(201, UserSchema)
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

        user = UserModel(username=user_data["username"], is_active=False)
        user.password = user_data["password"]
        user.roles.append(default_role)

        try:
            db.session.add(user)
            db.session.commit()
            current_app.logger.info(f"User created successfully: {user.username}")
            return user 

        except IntegrityError:
            db.session.rollback()
            current_app.logger.warning(f"Registration failed: Username '{user_data['username']}' already exists")
            abort(409, message="A user with that username already exists.")

        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Database error during registration: {str(e)}")
            abort(500, message="An internal server error occurred. Please try again later.")

