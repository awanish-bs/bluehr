from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_mail import Mail
import os
from dotenv import load_dotenv

# Load environment variables at the very beginning
load_dotenv()

# Logger for configuration
gemini_key = os.environ.get('GEMINI_API_KEY')
if gemini_key:
    # Remove any quotes or spaces
    gemini_key = gemini_key.strip().strip('"').strip("'")
    os.environ['GEMINI_API_KEY'] = gemini_key
    print(f"DEBUG: GEMINI_API_KEY from os.environ: SET (Starts with: {gemini_key[:4]}, Ends with: {gemini_key[-4:]})")
else:
    print("DEBUG: GEMINI_API_KEY from os.environ: NOT SET")

# Use a random secret key on each server restart to invalidate sessions
import secrets
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_urlsafe(32))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://bluehradmin:blue-hr-9(@bluehr-db.postgres.database.azure.com:5432/postgres')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Session timeout: 5 minutes
from datetime import timedelta
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)


# Email configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'mail.bluestack.in')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'hr@bluestack.in')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'hr@bluestack.in')

# API Keys and External Config
app.config['GEMINI_API_KEY'] = os.environ.get('GEMINI_API_KEY')
app.config['AZURE_STORAGE_CONNECTION_STRING'] = os.environ.get('AZURE_STORAGE_CONNECTION_STRING')

print(f"DEBUG: GEMINI_API_KEY in app.config: {'SET' if app.config['GEMINI_API_KEY'] else 'NOT SET'}")

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'index'
mail = Mail(app)

from flask import session, request

# Make session permanent and refresh on each request
@app.before_request
def make_session_permanent():
	session.permanent = True

from app import routes