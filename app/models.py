from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from datetime import datetime, timedelta

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(64), nullable=False)
    last_name = db.Column(db.String(64), nullable=False)
    employee_id = db.Column(db.String(32), index=True, unique=True, nullable=False)
    email = db.Column(db.String(120), index=True, unique=True, nullable=False)
    phone_number = db.Column(db.String(20))
    password_hash = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, default=False)
    reset_token = db.Column(db.String(100), unique=True)
    reset_token_expiry = db.Column(db.DateTime)
    payslips = db.relationship('Payslip', backref='employee', lazy='dynamic')
    profile = db.relationship('Profile', back_populates='user', uselist=False, cascade="all, delete-orphan")
    profile = db.relationship('Profile', back_populates='user', uselist=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_reset_token(self):
        self.reset_token = secrets.token_urlsafe(32)
        self.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
        return self.reset_token
    
    def verify_reset_token(self, token):
        if self.reset_token == token and self.reset_token_expiry > datetime.utcnow():
            return True
        return False

class Payslip(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    file_path = db.Column(db.String(256))
    month_year = db.Column(db.String(7))  # Format: YYYY-MM
    upload_date = db.Column(db.DateTime, server_default=db.func.now())

class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date_of_birth = db.Column(db.Date)
    address = db.Column(db.String(256))
    aadhar_number = db.Column(db.String(12), unique=True)
    pan_number = db.Column(db.String(10), unique=True)
    bank_name = db.Column(db.String(128))
    bank_account_number = db.Column(db.String(32))
    ifsc_code = db.Column(db.String(11))
    user = db.relationship('User', back_populates='profile')
