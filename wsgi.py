"""
WSGI entry point for Azure App Service
"""
from dotenv import load_dotenv
load_dotenv()  # Load environment variables from .env file

from app import app, db
from app import routes  # Import routes to register them with the app

# Initialize database tables
with app.app_context():
    db.create_all()

# This is the WSGI application
application = app

if __name__ == '__main__':
    app.run()
