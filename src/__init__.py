import os

from flask import Flask
from flask_smorest import Api
from src.extensions.database import db
from flask_migrate import Migrate

from src.config import get_config
from src.config.logging import configure_logger

from src.commands import register_commands
from src.common.errors import register_error_handlers

from flask_jwt_extended import JWTManager

from src.api import api_blp

def create_app(config=None):
    app = Flask(__name__)

    if config is None:
        config = get_config()  
    app.config.from_object(config)

    # Set up logging
    log_path = os.path.join(app.config.get("LOG_DIR", "src/logs"), "app.log")
    app.logger = configure_logger(log_path, debug_mode=app.config["DEBUG"])

    db.init_app(app)
    migrate = Migrate(app, db)
    api = Api(app)

    jwt = JWTManager(app)

    # Register CLI commands
    register_commands(app)
    register_error_handlers(app)

    app.register_blueprint(api_blp)
    
    return app

