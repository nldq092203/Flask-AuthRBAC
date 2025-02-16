import click
from flask import current_app
from src.seed import run_seeding

@click.command("seed")
def seed():
    """Seeds the database with initial data (roles, admin users, etc.)."""
    app = current_app._get_current_object()
    
    with app.app_context():
        run_seeding()
        click.echo("Database seeding completed.")        

