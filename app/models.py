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


class EmploymentHistory(db.Model):
    """Stores employment history for employees in JSON format"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    # Store employment records as JSON: [{"company_name": "", "designation": "", "start_date": "", "end_date": ""}, ...]
    employment_data = db.Column(db.Text, default='[]')  # JSON string
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())
    user = db.relationship('User', backref=db.backref('employment_history', uselist=False))


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256), nullable=False)
    original_filename = db.Column(db.String(256), nullable=False)
    file_type = db.Column(db.String(128))
    blob_url = db.Column(db.String(512), nullable=False)
    description = db.Column(db.String(512))
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_common = db.Column(db.Boolean, default=False)
    target_employee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    uploaded_by = db.relationship('User', foreign_keys=[uploaded_by_id])
    target_employee = db.relationship('User', foreign_keys=[target_employee_id])

# HR/Finance Document Model
class HRFinanceDocument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256), nullable=False)
    original_filename = db.Column(db.String(256), nullable=False)
    doc_type = db.Column(db.String(64), nullable=False)  # HR or Finance
    comments = db.Column(db.String(256))
    blob_url = db.Column(db.String(512), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploaded_by = db.relationship('User', foreign_keys=[uploaded_by_id])


class ChatMessage(db.Model):
    """Stores chat messages between users and the HR Policy Assistant chatbot"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text, nullable=False)
    referenced_documents = db.Column(db.Text)  # JSON string of document IDs
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('chat_messages', lazy='dynamic'))
