import os

from flask import Flask
from flask_smorest import Api
from src.extensions.database import db
from flask_migrate import Migrate

from src.config import get_config

from src.commands import register_commands

def create_app(config=None):
    app = Flask(__name__)

    if config is None:
        config = get_config()  
    app.config.from_object(config)

    db.init_app(app)
    migrate = Migrate(app, db)
    api = Api(app)

    # Register CLI commands
    register_commands(app)
    
    return app

