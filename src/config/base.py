import os
from abc import ABC, abstractmethod

class BaseConfig(ABC):
    """Base configuration with default settings shared across environments."""

    # General Settings
    @property
    @abstractmethod
    def DEBUG(self):
        """Must be defined in subclass."""
        pass
    PROPAGATE_EXCEPTIONS = True  

    # Database Configuration
    @property
    @abstractmethod
    def SQLALCHEMY_DATABASE_URI(self):
        """Must be defined in subclass."""
        pass
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # API Documentation (OpenAPI / Swagger)
    API_TITLE = "Skeleton Authentication and RBAC"
    API_VERSION = "v1"
    OPENAPI_VERSION = "3.0.3"
    OPENAPI_URL_PREFIX = "/"
    OPENAPI_SWAGGER_UI_PATH = "/swagger-ui"
    OPENAPI_SWAGGER_UI_URL = "https://cdn.jsdelivr.net/npm/swagger-ui-dist/"
    
    SEED_ADMIN = False