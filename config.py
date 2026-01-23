import os
from dotenv import load_dotenv

# Determine the absolute path to the directory containing run.py
basedir = os.path.abspath(os.path.join(os.path.dirname(__file__)))

# Construct the path to the .env file
dotenv_path = os.path.join(basedir, '.env')

# Load the .env file
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)
else:
    print("Warning: .env file not found. Please ensure it exists in the root directory.")

class Config:
    """Set Flask configuration from .env file."""
    # General Config
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    FLASK_APP = os.environ.get('FLASK_APP')
    FLASK_ENV = os.environ.get('FLASK_ENV')

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql://bluehradmin:blue-hr-9(@bluehr-db.postgres.database.azure.com:5432/postgres')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Email
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 25)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS') is not None
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    ADMINS = ['your-email@example.com']

    # API Keys
    GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')
