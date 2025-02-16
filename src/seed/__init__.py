from .seed_admin import create_admin
from .seed_roles import insert_roles
from src.config import get_config

def run_seeding():
    """Runs all seed functions based on config."""
    config = get_config()

    insert_roles()  

    if getattr(config, "SEED_ADMIN", False):
        create_admin()