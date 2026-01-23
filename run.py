from dotenv import load_dotenv
load_dotenv()  # Load environment variables from .env file

from app import app, db
from app.models import User
import os

if __name__ == '__main__':
    # Explicitly load .env file from the project root
    from dotenv import load_dotenv
    dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
    if os.path.exists(dotenv_path):
        load_dotenv(dotenv_path)

    with app.app_context():
        db.create_all()
    app.run(debug=True)
