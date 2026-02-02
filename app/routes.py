from flask import render_template, flash, redirect, url_for, request, jsonify, send_file
from flask_login import login_user, logout_user, current_user, login_required
from flask_mail import Message
from app import app, db, mail
from app.models import User, Payslip, Profile, EmploymentHistory, Document, HRFinanceDocument, ChatMessage
import json
@app.route('/admin/hr_finance_documents', methods=['GET'])
@login_required
def admin_get_hr_finance_documents():
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    docs = HRFinanceDocument.query.order_by(HRFinanceDocument.upload_date.desc()).all()
    doc_list = []
    for doc in docs:
        doc_list.append({
            'id': doc.id,
            'original_filename': doc.original_filename,
            'doc_type': doc.doc_type,
            'comments': doc.comments,
            'upload_date': doc.upload_date.strftime('%Y-%m-%d %H:%M'),
            'blob_url': doc.blob_url
        })
    return jsonify(doc_list)

@app.route('/admin/hr_finance_documents/upload', methods=['POST'])
@login_required
def admin_upload_hr_finance_document():
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    if 'document' not in request.files:
        flash('No file part')
        return redirect(url_for('admin_dashboard', _anchor='hr'))
    file = request.files['document']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('admin_dashboard', _anchor='hr'))
    doc_type = request.form.get('doc_type')
    comments = request.form.get('comments')
    original_filename = file.filename
    file_extension = os.path.splitext(original_filename)[1]
    unique_filename = f"{uuid.uuid4()}{file_extension}"
    try:
        blob_url = upload_blob(file.stream, unique_filename)
        new_doc = HRFinanceDocument(
            filename=unique_filename,
            original_filename=original_filename,
            doc_type=doc_type,
            comments=comments,
            blob_url=blob_url,
            uploaded_by_id=current_user.id
        )
        db.session.add(new_doc)
        db.session.commit()
        flash('Document uploaded successfully.')
    except Exception as e:
        flash(f'Error uploading document: {e}')
    return redirect(url_for('admin_dashboard') + '#hr')

@app.route('/admin/hr_finance_documents/delete/<int:doc_id>', methods=['POST'])
@login_required
def admin_delete_hr_finance_document(doc_id):
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('admin_dashboard', _anchor='hr'))
    doc = HRFinanceDocument.query.get_or_404(doc_id)
    try:
        if delete_blob(doc.filename):
            db.session.delete(doc)
            db.session.commit()
            flash('Document deleted successfully.')
        else:
            flash('Error deleting document from storage.')
    except Exception as e:
        flash(f'Error deleting document: {e}')
    return redirect(url_for('admin_dashboard') + '#hr')
from werkzeug.utils import secure_filename
import os
import json
from datetime import datetime
from app.utils.blob_storage import upload_blob, delete_blob, get_blob_sas_url
import uuid


# Route to delete all users except current admin
@app.route('/admin_delete_all_users', methods=['POST'])
@login_required
def admin_delete_all_users():
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('index'))

    # Find all users to delete
    users_to_delete = User.query.filter(User.id != current_user.id).all()
    for user in users_to_delete:
        # Delete associated profiles
        if user.profile:
            db.session.delete(user.profile)
        # Delete associated payslips
        Payslip.query.filter_by(user_id=user.id).delete()
        # Delete the user
        db.session.delete(user)

    db.session.commit()
    flash('All users (except current admin) and all associated data have been deleted.')
    return redirect(url_for('admin_dashboard') + '#admin')

@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
def index():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('employee_dashboard'))
    if request.method == 'POST':
        login_id = request.form['login_id']
        password = request.form['password']
        user = User.query.filter((User.email == login_id) | (User.employee_id == login_id)).first()
        if user is None or not user.check_password(password):
            flash('Invalid Email/Employee ID or password')
            return redirect(url_for('index'))
        login_user(user, remember=True)
        if user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('employee_dashboard'))
    return render_template('index.html')



@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/employee_dashboard')
@login_required
def employee_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    payslips = current_user.payslips.all()
    return render_template('employee_dashboard.html', payslips=payslips, user=current_user)


# User profile page
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if not current_user.profile:
        new_profile = Profile(user_id=current_user.id)
        db.session.add(new_profile)
        db.session.commit()
    else:
        # Ensure user_id is always set (fix for orphaned profiles)
        if current_user.profile.user_id is None:
            current_user.profile.user_id = current_user.id
            db.session.commit()

    if request.method == 'POST':
        import re
        current_user.first_name = request.form['first_name']
        current_user.last_name = request.form['last_name']
        current_user.email = request.form['email']
        phone_number = request.form['phone_number']
        aadhar_number = request.form['aadhar_number']
        pan_number = request.form['pan_number']
        bank_account_number = request.form['bank_account_number']

        # Email validation
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, current_user.email):
            flash('Invalid email address.')
            return redirect(url_for('employee_dashboard', _anchor='profile'))

        # Phone number validation (at least 10 digits)
        if phone_number and (not phone_number.isdigit() or len(phone_number) < 10):
            flash('Phone number must be at least 10 digits.')
            return redirect(url_for('employee_dashboard', _anchor='profile'))

        # Aadhar validation (12 digits)
        if aadhar_number and (not aadhar_number.isdigit() or len(aadhar_number) != 12):
            flash('Aadhar must be a 12 digit number.')
            return redirect(url_for('employee_dashboard', _anchor='profile'))

        # PAN validation (alphanumeric, length 10)
        if pan_number and (not re.match(r'^[A-Za-z0-9]{10}$', pan_number)):
            flash('PAN must be alphanumeric and 10 characters long.')
            return redirect(url_for('employee_dashboard', _anchor='profile'))

        # Bank account number must be numeric
        if bank_account_number and not bank_account_number.isdigit():
            flash('Bank account number must be numeric.')
            return redirect(url_for('employee_dashboard', _anchor='profile'))

        current_user.phone_number = phone_number
        current_user.profile.date_of_birth = datetime.strptime(request.form['date_of_birth'], '%Y-%m-%d').date() if request.form['date_of_birth'] else None
        current_user.profile.address = request.form['address']
        current_user.profile.aadhar_number = aadhar_number or None
        current_user.profile.pan_number = pan_number or None
        current_user.profile.bank_name = request.form['bank_name']
        current_user.profile.bank_account_number = bank_account_number
        current_user.profile.ifsc_code = request.form['ifsc_code']

        db.session.commit()
        flash('Your profile has been updated.')
        return redirect(url_for('employee_dashboard', _anchor='profile'))
    return render_template('profile.html', user=current_user)

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('employee_dashboard'))
    employees = User.query.filter_by(is_admin=False).all()
    all_users = User.query.all()
    # Gather payslips for all employees
    employee_payslips = {}
    for emp in employees:
        employee_payslips[emp] = emp.payslips.order_by(Payslip.upload_date.desc()).all()
    return render_template('admin_dashboard.html', employees=employees, employee_payslips=employee_payslips, all_users=all_users)

@app.route('/employee_view/<int:user_id>')
@login_required
def employee_view(user_id):
    if not current_user.is_admin:
        return redirect(url_for('employee_dashboard'))
    
    employee = User.query.get_or_404(user_id)
    payslips = employee.payslips.all()
    
    # Fetch employment history
    history = EmploymentHistory.query.filter_by(user_id=employee.id).first()
    employee_history = json.loads(history.employment_data) if history else []
    
    # Fetch documents
    documents = Document.query.filter(
        (Document.is_common == True) | (Document.target_employee_id == employee.id)
    ).order_by(Document.upload_date.desc()).all()
    
    return render_template('employee_view.html', employee=employee, user=employee, payslips=payslips, employee_history=employee_history, documents=documents)

@app.route('/admin/employee_details/<int:user_id>')
@login_required
def admin_employee_details(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    employee = User.query.get_or_404(user_id)
    payslips = employee.payslips.all()
    
    # Fetch employment history
    history = EmploymentHistory.query.filter_by(user_id=employee.id).first()
    employee_history = json.loads(history.employment_data) if history else []
    
    # Fetch documents
    documents = Document.query.filter(
        (Document.is_common == True) | (Document.target_employee_id == employee.id)
    ).order_by(Document.upload_date.desc()).all()
    
    return render_template('employee_detail_partial.html', employee=employee, user=employee, payslips=payslips, employee_history=employee_history, documents=documents)



@app.route('/upload_payslip', methods=['POST'])
@login_required
def upload_payslip():
    if not current_user.is_admin:
        return redirect(url_for('employee_dashboard'))
    
    employee_id = request.form['employee_id']
    month_year = request.form['month_year']
    file = request.files['payslip']
    
    if file:
        filename = secure_filename(file.filename)
        payslip_dir = os.path.join(app.root_path, 'static/payslips', employee_id)
        os.makedirs(payslip_dir, exist_ok=True)
        file_path = os.path.join(payslip_dir, filename)
        file.save(file_path)
        
        payslip = Payslip(user_id=employee_id, file_path=f'payslips/{employee_id}/{filename}', month_year=month_year)
        db.session.add(payslip)
        db.session.commit()
        flash('Payslip uploaded successfully')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    # Only allow admin access to this route
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        import re
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        employee_id = request.form['employee_id']
        email = request.form['email']
        phone_number = request.form.get('phone_number', '')
        password = request.form['password']
        is_admin = 'is_admin' in request.form
        aadhar_number = request.form.get('aadhar_number', '')
        pan_number = request.form.get('pan_number', '')
        bank_account_number = request.form.get('bank_account_number', '')


        # Required fields validation
        if not first_name.strip():
            flash('First Name is required.')
            return render_template('create_user.html', form_data=request.form)
        if not last_name.strip():
            flash('Last Name is required.')
            return render_template('create_user.html', form_data=request.form)
        if not employee_id.strip():
            flash('Employee ID is required.')
            return render_template('create_user.html', form_data=request.form)
        if not password.strip():
            flash('Password is required.')
            return render_template('create_user.html', form_data=request.form)

        # Employee ID must be numeric
        if not employee_id.isdigit():
            flash('Employee ID must be numeric.')
            return render_template('create_user.html', form_data=request.form)

        # Email validation
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, email):
            flash('Invalid email address.')
            return render_template('create_user.html', form_data=request.form)

        # Phone number validation (at least 10 digits)
        if phone_number and (not phone_number.isdigit() or len(phone_number) < 10):
            flash('Phone number must be at least 10 digits.')
            return render_template('create_user.html', form_data=request.form)

        # Aadhar validation (12 digits)
        if aadhar_number and (not aadhar_number.isdigit() or len(aadhar_number) != 12):
            flash('Aadhar must be 12 digit number.')
            return render_template('create_user.html', form_data=request.form)

        # PAN validation (alphanumeric, length 10)
        if pan_number and (not re.match(r'^[A-Za-z0-9]{10}$', pan_number)):
            flash('PAN must be alphanumeric and 10 characters long.')
            return render_template('create_user.html', form_data=request.form)

        # Bank account number must be numeric
        if bank_account_number and not bank_account_number.isdigit():
            flash('Bank account number must be numeric.')
            return render_template('create_user.html', form_data=request.form)

        existing_employee = User.query.filter_by(employee_id=employee_id).first()
        if existing_employee:
            flash('Employee ID already exists. Please use a different one.')
            return render_template('create_user.html', form_data=request.form)

        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Email already exists. Please use a different email.')
            return render_template('create_user.html', form_data=request.form)

        user = User(first_name=first_name, last_name=last_name, employee_id=employee_id, email=email, phone_number=phone_number, is_admin=is_admin)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        # Save profile details if provided
        if aadhar_number or pan_number or bank_account_number:
            profile = Profile(user_id=user.id)
            profile.aadhar_number = aadhar_number or None
            profile.pan_number = pan_number or None
            profile.bank_account_number = bank_account_number or None
            db.session.add(profile)
            db.session.commit()
        flash('User created successfully')
        return redirect(url_for('admin_dashboard'))
    return render_template('create_user.html')

@app.route('/admin/create_user', methods=['POST'])
@login_required
def admin_create_user():
    # Only allow admin access to this route
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('index'))
    
    import re
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    employee_id = request.form['employee_id']
    email = request.form['email']
    phone_number = request.form.get('phone_number', '')
    password = request.form['password']
    is_admin = 'is_admin' in request.form
    aadhar_number = request.form.get('aadhar_number', '')
    pan_number = request.form.get('pan_number', '')
    bank_account_number = request.form.get('bank_account_number', '')

    # Required fields validation
    if not first_name.strip():
        flash('First Name is required.')
        return redirect(url_for('admin_dashboard'))
    if not last_name.strip():
        flash('Last Name is required.')
        return redirect(url_for('admin_dashboard'))
    if not employee_id.strip():
        flash('Employee ID is required.')
        return redirect(url_for('admin_dashboard'))
    if not password.strip():
        flash('Password is required.')
        return redirect(url_for('admin_dashboard'))

    # Employee ID must be numeric
    if not employee_id.isdigit():
        flash('Employee ID must be numeric.')
        return redirect(url_for('admin_dashboard'))

    # Email validation
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        flash('Invalid email address.')
        return redirect(url_for('admin_dashboard'))

    # Phone number validation (at least 10 digits)
    if phone_number and (not phone_number.isdigit() or len(phone_number) < 10):
        flash('Phone number must be at least 10 digits.')
        return redirect(url_for('admin_dashboard'))

    # Aadhar validation (12 digits)
    if aadhar_number and (not aadhar_number.isdigit() or len(aadhar_number) != 12):
        flash('Aadhar must be 12 digit number.')
        return redirect(url_for('admin_dashboard'))

    # PAN validation (alphanumeric, length 10)
    if pan_number and (not re.match(r'^[A-Za-z0-9]{10}$', pan_number)):
        flash('PAN must be alphanumeric and 10 characters long.')
        return redirect(url_for('admin_dashboard'))

    # Bank account number must be numeric
    if bank_account_number and not bank_account_number.isdigit():
        flash('Bank account number must be numeric.')
        return redirect(url_for('admin_dashboard'))

    existing_employee = User.query.filter_by(employee_id=employee_id).first()
    if existing_employee:
        flash('Employee ID already exists. Please use a different one.')
        return redirect(url_for('admin_dashboard'))

    existing_email = User.query.filter_by(email=email).first()
    if existing_email:
        flash('Email already exists. Please use a different email.')
        return redirect(url_for('admin_dashboard'))

    try:
        user = User(first_name=first_name, last_name=last_name, employee_id=employee_id, email=email, phone_number=phone_number, is_admin=is_admin)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        # Save profile details if provided
        if aadhar_number or pan_number or bank_account_number:
            profile = Profile(user_id=user.id)
            profile.aadhar_number = aadhar_number or None
            profile.pan_number = pan_number or None
            profile.bank_account_number = bank_account_number or None
            db.session.add(profile)
            db.session.commit()
            
        flash('User created successfully!')
    except Exception as e:
        db.session.rollback()
        flash('Error creating user. Please try again.')
    
    return redirect(url_for('admin_dashboard'))

# Admin Reset Password (admin can reset any user's password)
@app.route('/admin_reset_password/<int:user_id>', methods=['POST'])
@login_required
def admin_reset_password(user_id):
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('index'))
    
    user = User.query.get(user_id)
    if not user:
        flash('User not found.')
        return redirect(url_for('admin_dashboard'))
    
    new_password = request.form['new_password']
    user.set_password(new_password)
    db.session.commit()
    flash(f'Password reset successfully for user {user.first_name}.')
    return redirect(url_for('admin_dashboard'))

# Admin Delete User
@app.route('/admin_delete_user/<int:user_id>', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('index'))
    
    user = User.query.get(user_id)
    if not user:
        flash('User not found.')
        return redirect(url_for('admin_dashboard'))
    
    # Prevent admin from deleting themselves
    if user.id == current_user.id:
        flash('You cannot delete your own account.')
        return redirect(url_for('admin_dashboard'))
    
    user_first_name = user.first_name
    # Delete associated payslips first
    Payslip.query.filter_by(user_id=user.id).delete()
    # Delete the user
    db.session.delete(user)
    db.session.commit()
    flash(f'User {user_first_name} and all associated data have been deleted successfully.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin_edit_user/<int:user_id>', methods=['POST'])
@login_required
def admin_edit_user(user_id):
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('index'))
    
    user = User.query.get(user_id)
    if not user:
        flash('User not found.')
        return redirect(url_for('admin_dashboard'))

    user.first_name = request.form['first_name']
    user.last_name = request.form['last_name']
    user.email = request.form['email']
    
    db.session.commit()
    flash(f'User {user.first_name} has been updated.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin_delete_payslip/<int:payslip_id>', methods=['POST'])
@login_required
def admin_delete_payslip(payslip_id):
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('index'))
    payslip = Payslip.query.get(payslip_id)
    if not payslip:
        flash('Payslip not found.')
        return redirect(url_for('admin_dashboard'))
    db.session.delete(payslip)
    db.session.commit()
    flash('Payslip deleted successfully.')
    return redirect(url_for('admin_dashboard'))


# Employee request password change (sends email)
@app.route('/request_password_change', methods=['GET', 'POST'])
@login_required
def request_password_change():
    if request.method == 'POST':
        user = current_user
        token = user.generate_reset_token()
        db.session.commit()
        
        # Send password reset email
        reset_url = url_for('reset_password_with_token', token=token, _external=True)
        try:
            msg = Message(
                subject='Password Reset Request - BlueHR',
                recipients=[user.email]
            )
            msg.html = f'''
            <h2>Password Reset Request</h2>
            <p>Hi {user.first_name},</p>
            <p>You have requested to reset your password. Click the link below to reset your password:</p>
            <p><a href="{reset_url}">Reset Password</a></p>
            <p>This link will expire in 1 hour.</p>
            <p>If you did not request this, please ignore this email.</p>
            <br>
            <p>Best regards,</p>
            <p>BlueHR Team</p>
            '''
            mail.send(msg)
            flash('Password reset link has been sent to your email address.')
        except Exception as e:
            flash(f'Error sending email. Please contact administrator.')
            print(f"Email error: {e}")
        
        return redirect(url_for('employee_dashboard'))
    
    return render_template('change_password.html')


# Reset password with token (from email link)
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_with_token(token):
    user = User.query.filter_by(reset_token=token).first()
    
    if not user or not user.verify_reset_token(token):
        flash('Invalid or expired reset link.')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('Passwords do not match.')
            return render_template('reset_password.html', token=token)
        
        user.set_password(new_password)
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()
        flash('Your password has been reset successfully. Please log in with your new password.', 'success')
        return redirect(url_for('index'))
    
    return render_template('reset_password.html', token=token)


# Forgot password (from login page)
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        employee_id = request.form['employee_id']
        email = request.form['email']
        
        # Check if user exists with matching employee_id and email
        user = User.query.filter_by(employee_id=employee_id, email=email).first()
        
        if not user:
            flash('No account found with that Employee ID and Email combination.')
            return render_template('forgot_password.html')
        
        # Generate reset token and send email
        token = user.generate_reset_token()
        db.session.commit()
        
        reset_url = url_for('reset_password_with_token', token=token, _external=True)
        try:
            msg = Message(
                subject='Password Reset Request - BlueHR',
                recipients=[user.email]
            )
            msg.html = f'''
            <h2>Password Reset Request</h2>
            <p>Hi {user.first_name},</p>
            <p>You have requested to reset your password. Click the link below to reset your password:</p>
            <p><a href="{reset_url}">Reset Password</a></p>
            <p>This link will expire in 1 hour.</p>
            <p>If you did not request this, please ignore this email.</p>
            <br>
            <p>Best regards,</p>
            <p>BlueHR Team</p>
            '''
            mail.send(msg)
            flash('Password reset link has been sent to your email address.')
        except Exception as e:
            flash('Error sending email. Please contact administrator.')
            print(f"Email error: {e}")
        
        return redirect(url_for('index'))
    
    return render_template('forgot_password.html')


# Employment History - Get current employee's history
@app.route('/employment_history', methods=['GET'])
@login_required
def get_employment_history():
    history = EmploymentHistory.query.filter_by(user_id=current_user.id).first()
    if history:
        employment_data = json.loads(history.employment_data)
    else:
        employment_data = []
    return jsonify(employment_data)


# Employment History - Save employee's history
@app.route('/employment_history', methods=['POST'])
@login_required
def save_employment_history():
    data = request.get_json()
    if data is None:
        return jsonify({'error': 'Invalid data'}), 400
    
    history = EmploymentHistory.query.filter_by(user_id=current_user.id).first()
    if not history:
        history = EmploymentHistory(user_id=current_user.id)
        db.session.add(history)
    
    history.employment_data = json.dumps(data)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Employment history saved successfully'})


# Admin - View all employees' employment history
@app.route('/admin/employment_history')
@login_required
def admin_get_all_employment_history():
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    employees = User.query.filter_by(is_admin=False).all()
    result = []
    for emp in employees:
        history = EmploymentHistory.query.filter_by(user_id=emp.id).first()
        employment_data = json.loads(history.employment_data) if history else []
        result.append({
            'employee_id': emp.employee_id,
            'first_name': emp.first_name,
            'last_name': emp.last_name,
            'email': emp.email,
            'employment_history': employment_data
        })
    return jsonify(result)

# Document Management - Admin
@app.route('/admin/documents', methods=['GET'])
@login_required
def admin_get_documents():
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    documents = Document.query.order_by(Document.upload_date.desc()).all()
    
    doc_list = []
    for doc in documents:
        doc_list.append({
            'id': doc.id,
            'original_filename': doc.original_filename,
            'file_type': doc.file_type,
            'upload_date': doc.upload_date.strftime('%Y-%m-%d %H:%M'),
            'is_common': 'Yes' if doc.is_common else 'No',
            'target': 'All' if doc.is_common else (doc.target_employee.first_name + ' ' + doc.target_employee.last_name if doc.target_employee else 'N/A'),
            'description': doc.description or ''
        })
        
    return jsonify(doc_list)

@app.route('/admin/documents/upload', methods=['POST'])
@login_required
def admin_upload_document():
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403

    if 'document' not in request.files:
        flash('No file part')
        return redirect(url_for('admin_dashboard'))

    file = request.files['document']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('admin_dashboard'))

    target_type = request.form.get('target_type')
    employee_id = request.form.get('employee_id')
    description = request.form.get('description', '').strip()

    is_common = target_type == 'all'
    target_employee_id = None
    
    if not is_common and employee_id:
        # Look up the user by their database id (not employee_id string)
        target_employee_id = int(employee_id)

    if file:
        original_filename = file.filename
        file_extension = os.path.splitext(original_filename)[1]
        unique_filename = f"{uuid.uuid4()}{file_extension}"
        
        try:
            blob_url = upload_blob(file.stream, unique_filename)
            
            new_doc = Document(
                filename=unique_filename,
                original_filename=original_filename,
                file_type=file.mimetype,
                blob_url=blob_url,
                description=description,
                uploaded_by_id=current_user.id,
                is_common=is_common,
                target_employee_id=target_employee_id
            )
            db.session.add(new_doc)
            db.session.commit()
            flash('Document uploaded successfully.')
        except Exception as e:
            flash(f'Error uploading document: {e}')

    return redirect(url_for('admin_dashboard', _anchor='documents'))

@app.route('/admin/documents/delete/<int:doc_id>', methods=['POST'])
@login_required
def admin_delete_document(doc_id):
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('admin_dashboard'))

    doc = Document.query.get_or_404(doc_id)
    
    try:
        if delete_blob(doc.filename):
            db.session.delete(doc)
            db.session.commit()
            flash('Document deleted successfully.')
        else:
            flash('Error deleting document from storage.')
    except Exception as e:
        flash(f'Error deleting document: {e}')
        
    return redirect(url_for('admin_dashboard', _anchor='documents'))

# Document Management - Employee
@app.route('/documents', methods=['GET'])
@login_required
def get_documents():
    # Documents for everyone + documents for the current user
    documents = Document.query.filter(
        (Document.is_common == True) | (Document.target_employee_id == current_user.id)
    ).order_by(Document.upload_date.desc()).all()
    
    doc_list = [{
        'id': doc.id,
        'original_filename': doc.original_filename,
        'upload_date': doc.upload_date.strftime('%Y-%m-%d'),
        'is_common': 'Company Policy' if doc.is_common else 'Personal',
        'description': doc.description or ''
    } for doc in documents]
    
    return jsonify(doc_list)

@app.route('/documents/download/<int:doc_id>', methods=['GET'])
@login_required
def download_document(doc_id):
    doc = Document.query.get_or_404(doc_id)

    # Security check: user can only download common docs or their own
    if not doc.is_common and doc.target_employee_id != current_user.id:
        # Admin can download any document
        if not current_user.is_admin:
            flash('Access denied.')
            return redirect(url_for('employee_dashboard'))

    try:
        sas_url = get_blob_sas_url(doc.filename)
        return redirect(sas_url)
    except Exception as e:
        flash(f"Error generating download link: {e}")
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('employee_dashboard'))


@app.route('/chatbot', methods=['GET', 'POST'])
@login_required
def chatbot():
    """HR Policy Assistant chatbot interface"""
    chat_history = ChatMessage.query.filter_by(user_id=current_user.id)\
        .order_by(ChatMessage.created_at.desc()).limit(20).all()
    
    if request.method == 'POST':
        user_message = request.form.get('message')
        
        if user_message:
            try:
                # Lazy import to ensure .env is loaded first
                from app.services.chatbot_service import ChatbotService
                
                # Get response from chatbot
                chatbot_service = ChatbotService()
                response_text, doc_ids = chatbot_service.get_response(user_message)
                
                # Save to database
                chat_msg = ChatMessage(
                    user_id=current_user.id,
                    message=user_message,
                    response=response_text,
                    referenced_documents=json.dumps(doc_ids)
                )
                db.session.add(chat_msg)
                db.session.commit()
                
                # Get document details for download links
                documents = Document.query.filter(Document.id.in_(doc_ids)).all() if doc_ids else []
                doc_info = [{'id': d.id, 'filename': d.original_filename} for d in documents]
                
                return jsonify({
                    'success': True,
                    'response': response_text,
                    'documents': doc_info
                })
            except Exception as e:
                return jsonify({
                    'success': False,
                    'response': f"Error: {str(e)}",
                    'documents': []
                })
    
    return render_template('chatbot.html', chat_history=chat_history)


@app.route('/chatbot/clear', methods=['POST'])
@login_required
def clear_chatbot():
    """Clear chat history for current user"""
    try:
        ChatMessage.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/chatbot/download/<int:doc_id>')
@login_required
def download_chatbot_document(doc_id):
    """Download policy documents from chatbot interface"""
    document = Document.query.get_or_404(doc_id)
    
    # Security check: only allow downloading policy documents (not payslips)
    excluded_keywords = ['payslip', 'salary', 'compensation', 'payroll', 'pay slip', 'pay-slip']
    filename_lower = document.filename.lower()
    original_lower = document.original_filename.lower()
    
    if any(keyword in filename_lower for keyword in excluded_keywords) or \
       any(keyword in original_lower for keyword in excluded_keywords):
        flash('Access denied to this document', 'danger')
        return redirect(url_for('chatbot'))
    
    try:
        # Generate SAS URL and redirect
        sas_url = get_blob_sas_url(document.filename)
        return redirect(sas_url)
    except Exception as e:
        flash(f"Error generating download link: {str(e)}")
        return redirect(url_for('chatbot'))
