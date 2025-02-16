import os
from .base import BaseConfig

class DevelopmentConfig(BaseConfig):
    @property
    def DEBUG(self):
        return True

    @property
    def SQLALCHEMY_DATABASE_URI(self):
        return os.getenv("DATABASE_URL", "sqlite:///dev.db")
    
    SEED_ADMIN = True
    