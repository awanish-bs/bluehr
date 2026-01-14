from dotenv import load_dotenv
load_dotenv()  # Load environment variables from .env file

from app import app, db
from app.models import User

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
