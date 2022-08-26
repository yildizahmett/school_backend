import math
from flask import request, jsonify, url_for, send_file
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import json
import os

from itsdangerous import URLSafeTimedSerializer

from scripts.util import EMPLOYEE_EDIT_CHANGEABLE_FIELDS, app, bcrypt, company_based_employee_rates, company_invite_total, employee_mail_queue, general_select_count, get_employment_rate, limiter, db_count_employee_fav, db_count_student_fav, db_filter_admin_count, db_filter_employee, db_filter_student_count, db_get_employee_for_fav, db_get_student_for_fav, get_companies, get_fav_amount, get_favourited_student_ids, get_my_favourites, get_programs, jwt, db, engine, get_specific_data, post_search_talent, search_statistics, student_mail_queue, update_company_name, update_is_activate_employees, update_is_activate_students, update_is_active_company, update_table_data, update_profile_data, random_id_generator, logging, db_filter_admin
from scripts.util import FRONTEND_LINK, DC_AD_STUDENT, DC_AD_COMPANIES, DC_AD_EMPLOYEES, DC_ST_GENERAL, DC_ST_ACTIVITIES, DC_ST_HARDSKILLS, DC_ST_JOB
from scripts.util import SAFE_TALENT_COLUMNS, UNSAFE_TALENT_COLUMNS, REPORTING_MAILS, select_fav, select_std
from scripts.models import Companies, Employees, Favourites, Reports, Students, Temps, Programs
from scripts.send_mail import send_mail


def generate_confirmation_token(email):
    try:
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])
    except Exception as e:
        log_body = f'generate_confirmation_token > ERROR : {repr(e)}'
        logging.warning(f'{log_body}')
        return -1


def confirm_token(token, expiration=18000):
    try:
        # 18000 is 5 hours.
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
        return email
    except:
        return False


@app.route('/student/upload-cv/<int:id>', methods=['POST'])
@limiter.limit("1/second;2/minute;5/hour;10/day", override_defaults=False)
@jwt_required()
def upload_cv(id):
    try:
        jwt_data = get_jwt_identity()
        user_type = jwt_data['user_type']
        email = jwt_data['email']

        if user_type != 'student':
            log_body = f'User: {email} | Wrong user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not a student'}), 401

        student = Students.query.filter_by(email=email, is_active=True).first()
        
        if not student:
            log_body = f'Student not found'
            logging.warning(f'User: {email} | {log_body}')
            return jsonify({'message': 'Student does not exist'}), 400

        if student.id != id:
            log_body = f'Student id does not match'
            logging.warning(f'User: {email} | {log_body}')
            return jsonify({'message': 'Student id does not match'}), 400

        if 'file' not in request.files:
            log_body = f'User: {email} | No file attached'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'No file attached'}), 400

        file = request.files['file']
        if file.filename == '':
            log_body = f'User: {email} | No file selected'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'No file selected'}), 400
        
        if (file.filename.split('.')[-1] != 'pdf' and not file):
            log_body = f'User: {email} | Wrong file type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Wrong file type'}), 400

        file.filename = "cv.pdf"
        filename = secure_filename(file.filename)
        
        current_directory = os.path.dirname(os.path.abspath(__file__))
        save_dir = current_directory + app.config['UPLOAD_FOLDER'] + "\\" + str(id) + "\\" + filename
        
        try:
            file.save(save_dir)
        except:
            os.mkdir(current_directory + app.config['UPLOAD_FOLDER'] + "\\" + str(id))
            file.save(save_dir)

        log_body = f'User: {email} | File uploaded'
        logging.info(f'{log_body}')
        return jsonify({'message': 'File uploaded'}), 201
    
    except Exception as e:
        log_body = f'User: {email} | {repr(e)}'
        logging.warning(f'{log_body}')
        return jsonify({'message': 'Something went wrong'}), 400


@app.route('/employee/download-cv/<int:student_id>', methods=['GET'])
@limiter.limit("1/second;5/minute;20/hour;100/day", override_defaults=False)
@jwt_required()
def employee_download_cv(student_id):
    try:
        jwt_data = get_jwt_identity()
        user_type = jwt_data['user_type']
        email = jwt_data['email']

        if user_type != 'employee':
            log_body = f'User: {email} | Wrong user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not authorized to perform this action'}), 401

        employee = Employees.query.filter_by(email=email, is_active=True).first()
        if not employee:
            log_body = f'Employee not found'
            logging.warning(f'User: {email} | {log_body}')
            return jsonify({'message': 'Employee does not exist'}), 400

        if employee.t_c != True:
            log_body = f'User: {email} | Terms and conditions not accepted'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Terms and conditions not accepted.'}), 400

        current_directory = os.path.dirname(os.path.abspath(__file__))
        save_dir = current_directory + app.config['UPLOAD_FOLDER'] + "\\" + str(student_id) + "\\cv.pdf"
        
        if not os.path.exists(save_dir):
            log_body = f'User: {email} | CV not found'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'CV not found'}), 400
        
        return send_file(save_dir, as_attachment=True)
    
    except Exception as e:
        log_body = f'User: {email} | {repr(e)}'
        logging.warning(f'{log_body}')
        return jsonify({'message': 'Something went wrong'}), 400

@app.route('/admin/download-cv/<int:student_id>', methods=['GET'])
@limiter.limit("1/second;5/minute;20/hour;100/day", override_defaults=False)
@jwt_required()
def download_cv(student_id):
    try:
        jwt_data = get_jwt_identity()
        user_type = jwt_data['user_type']
        
        if user_type != 'admin':
            log_body = f'Wrong user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not authorized to perform this action'}), 401

        current_directory = os.path.dirname(os.path.abspath(__file__))
        save_dir = current_directory + app.config['UPLOAD_FOLDER'] + "\\" + str(student_id) + "\\cv.pdf"
        
        if not os.path.exists(save_dir):
            log_body = f'CV not found'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'CV not found'}), 400
        
        return send_file(save_dir, as_attachment=True)
    
    except Exception as e:
        log_body = f'{repr(e)}'
        logging.warning(f'{log_body}')
        return jsonify({'message': 'Something went wrong'}), 400

@app.route('/email-verification/<token>')
@limiter.limit("3/second")
def email_verify(token):
    try:
        email = confirm_token(token)

        if not email:
            log_body = f'The confirmation link is invalid or has expired.'
            logging.warning(f'User: {email} | {log_body}')
            return jsonify({'message': 'The confirmation link is invalid or has expired.'}), 400

        temp_student = Temps.query.filter_by(email=email).first()

        if Students.query.filter_by(email=email).first():
            log_body = f'Email already verified'
            logging.warning(f'User: {email} | {log_body}')
            return jsonify({'message': 'Email already verified'}), 400

        # Transfer from Temps to Students Table
        student = Students(temp_student.email, temp_student.password, temp_student.name, temp_student.surname)
        db.session.add(student)
        db.session.delete(temp_student) # Remove temp student from Temps
        db.session.commit()

        log_body = f'User: {email} | Email verified'
        logging.info(f'{log_body}')
        return jsonify({'message': 'Email verified successfully'}), 200
    except Exception as e:
        log_body = f'Student > Email Verification > ERROR > {repr(e)}'
        logging.warning(f'User: {email} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/report', methods=['POST'])
@limiter.limit("3/second")
@jwt_required()
def report():
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if not (user_type == 'student' or user_type == 'employee' or user_type == 'admin'):
            log_body = f'You are not authorized to perform this action'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not authorized to perform this action'}), 401

        data = request.get_json()
        report_email = None
        if not user_type == 'admin':
            report_email = jwt_identity['email']

        report_user = user_type
        report_route = data['route']
        report_message = data['message']
        
        report = Reports(report_email, report_user, report_route, report_message)
        db.session.add(report)
        db.session.commit()

        # TODO: Send email to REPORTING_MAILS

    except Exception as e:
        log_body = f'report > ERROR > {repr(e)}'
        logging.warning(f'User: {"admin" if user_type == "admin" else report_email} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


# ========================================================================================
#   STUDENT Routes
# ========================================================================================
@app.route('/student/register', methods=['POST'])
@limiter.limit("3/second")
def student_register():
    try:
        data = request.get_json()
        email = data['email']
        password = data['password']
        name = data['name']
        surname = data['surname']

        old_student = Students.query.filter_by(email=email, is_active=True).first()

        if old_student:
            log_body = f'Student already exists'
            logging.warning(f'User: {email} | {log_body}')
            return jsonify({'message': 'Student already registered'}), 400

        temp_student = Temps.query.filter_by(email=email).first()
        if not temp_student:
            log_body = f'Student not found'
            logging.warning(f'User: {email} | {log_body}')
            return jsonify({'message': 'This email is not invited'}), 400

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        try:
            student = Students(email, hashed_password, name, surname)

            programs = []
            for i in range(len(temp_student.program_names)):

                program_to_add = {
                    "github_link": "",
                    "program_name": temp_student.program_names[i],
                    "program_code": temp_student.program_codes[i],
                    "summary": "",
                    "video_link": ""
                }

                programs.append(program_to_add)

            setattr(student, 'school_programs', programs)

            # Delete temp student from Temps
            db.session.delete(temp_student)

            db.session.add(student)
            db.session.commit()

            log_body = f'User: {email} | Student registered'
            logging.info(f'{log_body}')
            return jsonify({'message': 'Student created successfully'}), 200
        except Exception as e:
            log_body = f'Student > Register > Request Operation > ERROR > {repr(e)}'
            logging.warning(f'User: {email} | {log_body}')
            return jsonify({'message': 'Something went wrong'}), 500

    except Exception as e:
        log_body = f'Student > Register > ERROR : {repr(e)}'
        logging.warning(f'User: {email} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/student/login', methods=['POST'])
@limiter.limit("3/second")
def student_login():
    try:
        data = request.get_json()
        email = data['email']
        password = data['password']

        student = Students.query.filter_by(email=email, is_active=True).first()
        if not student:
            log_body = f'Student not found'
            logging.warning(f'User: {email} | {log_body}')
            return jsonify({'message': 'Student does not exist'}), 400

        token_identity = {'user_type': 'student', 'email': email, 'profile_complete': student.profile_complete}

        if bcrypt.check_password_hash(student.password, password):
            access_token = create_access_token(identity=token_identity)
            log_body = f'User: {email} | Student logged in'
            logging.info(f'{log_body}')
            return jsonify({'name': student.name, 'surname': student.surname, 'access_token': access_token}), 200
        else:
            log_body = f'User: {email} | Wrong password'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Incorrect password or email'}), 400
        
    except Exception as e:
        log_body = f'Student > Login > ERROR : {repr(e)}'
        logging.warning(f'User: {email} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


# ========================================================================================
#   Profile Update Section
# ========================================================================================
#   General, Activities, Hardskills, Softskills, Job, Settings
#   'Settings' route will be coded later -> features mail sending, changing email and password
@app.route('/student/profile-update/general', methods=['GET', 'POST'])
@limiter.limit("3/second")
@jwt_required()
def profile_update_general():
    return update_profile_data(request, get_jwt_identity(), Students, DC_ST_GENERAL)


@app.route('/student/profile-update/activities', methods=['GET', 'POST'])
@limiter.limit("3/second")
@jwt_required()
def profile_update_activities():
    return update_profile_data(request, get_jwt_identity(), Students, DC_ST_ACTIVITIES)


@app.route('/student/profile-update/hardskills', methods=['GET', 'POST'])
@limiter.limit("3/second")
@jwt_required()
def profile_update_hardskills():
    return update_profile_data(request, get_jwt_identity(), Students, DC_ST_HARDSKILLS)


@app.route('/student/profile-update/job', methods=['GET', 'POST'])
@limiter.limit("3/second")
@jwt_required()
def profile_update_job():
    return update_profile_data(request, get_jwt_identity(), Students, DC_ST_JOB)


@app.route('/student/profile-update/settings/change-password', methods=['POST'])
@limiter.limit("3/second")
@jwt_required()
def profile_update_settings():
    try:
        jwt_data = get_jwt_identity()
        user_type = jwt_data['user_type']
        email = jwt_data['email']

        if user_type != 'student':
            log_body = f'User: {email} | Wrong user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not a student'}), 401

        data = request.get_json()
        new_password = data['new_password']
        password = data['password']

        student = Students.query.filter_by(email=email, is_active=True).first()
        
        if not student:
            log_body = f'Student not found'
            logging.warning(f'User: {email} | {log_body}')
            return jsonify({'message': 'Student does not exist'}), 400

        if not bcrypt.check_password_hash(student.password, password):
            log_body = f'User: {email} | Wrong password'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Incorrect password'}), 400
        
        token = generate_confirmation_token([email, new_password])

        if token == -1:
            log_body = f'User: {email} | Token generation failed'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'An error has occured while trying to send email'}), 400

        confirm_url = FRONTEND_LINK + '/student/confirm-new-password/' + token
        msg = 'Please click the link to confirm your new password: {} '.format(confirm_url)
        subj = 'Confirm new password'
        student_mail_queue([email], msg, subj)

        log_body = f'User: {email} | Password change email sent'
        logging.info(f'{log_body}')
        return jsonify({'message': 'Verification email sent'}), 200
    except Exception as e:
        log_body = f'Student > Profile Update Settings > ERROR : {repr(e)}'
        logging.warning(f'User: {email} | {log_body}')
        return jsonify({'message': 'Something went wrong. ' + repr(e)}), 500


@app.route('/student/confirm-new-password/<token>')
@limiter.limit("3/second")
def student_confirm_new_password(token):
    try:
        email, new_password = confirm_token(token)

        if not email:
            log_body = f'User: {email} | Token expired'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'The confirmation link is invalid or has expired.'}), 400

        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        student = Students.query.filter_by(email=email, is_active=True).first()

        if not student:
            log_body = f'User: {email} | Student not found'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Student does not exist'}), 400

        setattr(student, 'password', hashed_password)
        db.session.commit()
        
        log_body = f'User: {email} | Password changed'
        logging.info(f'{log_body}')
        return jsonify({'message': 'Password changed successfully'}), 200
    except Exception as e:
        log_body = f'Student > Confirm New Password > ERROR : {repr(e)}'
        logging.warning(f'User: {email} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/student/forgot-password', methods=['POST'])
@limiter.limit("3/second")
def student_forgot_password():
    try:
        data = request.get_json()
        email = data['email']

        student = Students.query.filter_by(email=email, is_active=True).first()

        if not student:
            log_body = f'User: {email} | Student not found'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Student does not exist'}), 400
        
        token = generate_confirmation_token(email)

        if token == -1:
            log_body = f'User: {email} | Token generation failed'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'An error has occured while trying to send email.'}), 400

        confirm_url = FRONTEND_LINK + '/student/reset-password/' + token
        msg = 'Please click the link to reset your password: {} '.format(confirm_url)
        subj = 'Reset password'
        student_mail_queue([email], msg, subj)

        log_body = f'User: {email} | Password reset email sent'
        logging.info(f'{log_body}')
        return jsonify({'message': 'Verification email sent'}), 200
    except Exception as e:
        log_body = f'Student > Forgot Password > ERROR : {repr(e)}'
        logging.warning(f'User: {email} | {log_body}')
        return jsonify({'message': 'Something went wrong. ' + repr(e)}), 500


@app.route('/student/reset-password/<token>', methods=['POST'])
@limiter.limit("3/second")
def student_reset_password(token):
    try:
        data = request.get_json()
        new_password = data['new_password']

        email = confirm_token(token)

        if not email:
            log_body = f'User: {email} | Token expired'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'The confirmation link is invalid or has expired.'}), 400

        student = Students.query.filter_by(email=email, is_active=True).first()

        if not student:
            log_body = f'User: {email} | Student not found'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Student does not exist'}), 400

        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        setattr(student, 'password', hashed_password)
        db.session.commit()
        
        log_body = f'User: {email} | Password changed'
        logging.info(f'{log_body}')
        return jsonify({'message': 'Password reset successfully'}), 200
    except Exception as e:
        log_body = f'Student > Reset Password > ERROR : {repr(e)}'
        logging.warning(f'User: {email} | {log_body}')
        return jsonify({'message': 'Something went wrong. ' + repr(e)}), 500


# ========================================================================================
#   End of STUDENT Routes
# ========================================================================================


# ========================================================================================
#   EMPLOYEE Routes
# ========================================================================================
@app.route('/employee/register', methods=['POST'])
@limiter.limit("3/second")
def employee_register():
    try:
        data = request.get_json()
        email = data['email']
        password = data['password']
        name = data['name']
        surname = data['surname']
        special_id = data['special_id']

        company = Companies.query.filter_by(special_id=special_id, is_active=True).first()
        if not company:
            log_body = f'User: {email} | Company not found'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Special ID does not exist'}), 400

        company_users = company.company_users
        if not email in company_users:
            log_body = f'User: {email} | Not authorized to register'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Email is not approved'}), 400

        old_employee = Employees.query.filter_by(email=email, is_active=True).first()
        if old_employee:
            log_body = f'User: {email} | Employee already exists'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Email already exists'}), 400

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        employee = Employees(name, surname, email, hashed_password, company_id=company.id, company_name=company.company_name)

        db.session.add(employee)
        db.session.commit()

        log_body = f'User: {email} | Employee registered'
        logging.info(f'{log_body}')
        return jsonify({'message': 'User created successfully'}), 200
    except Exception as e:
        log_body = f'Employee > Register > ERROR : {repr(e)}'
        logging.warning(f'User: {email} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500
    
@app.route('/employee/login', methods=['POST'])
@limiter.limit("3/second")
def employee_login():
    try:
        data = request.get_json()
        email = data['email']
        password = data['password']

        employee = Employees.query.filter_by(email=email, is_active=True).first()

        if not employee:
            log_body = f'User: {email} | Employee not found'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Employee does not exist'}), 400

        token_identity = {'user_type': 'employee', 'email': email}

        if bcrypt.check_password_hash(employee.password, password):
            access_token = create_access_token(identity=token_identity)

            log_body = f'User: {email} | Employee logged in'
            logging.info(f'{log_body}')
            return jsonify({'name': employee.name, 'surname': employee.surname, 'access_token': access_token}), 200
        else:
            log_body = f'User: {email} | Invalid password'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Incorrect password or email'}), 400
    except Exception as e:
        log_body = f'Employee > Login > ERROR : {repr(e)}'
        logging.warning(f'User: {email} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500

@app.route('/employee/change-password', methods=['POST'])
@limiter.limit("3/second")
@jwt_required()
def employee_change_password():
    try:
        jwt_data = get_jwt_identity()
        user_type = jwt_data['user_type']
        email = jwt_data['email']

        if user_type != 'employee':
            log_body = f'User: {email} | Not authorized to change password'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not authorized to perform this action'}), 401

        data = request.get_json()
        new_password = data['new_password']
        password = data['password']

        employee = Employees.query.filter_by(email=email, is_active=True).first()

        if not employee:
            log_body = f'User: {email} | Employee not found'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Employee does not exist'}), 400

        if not bcrypt.check_password_hash(employee.password, password):
            log_body = f'User: {email} | Invalid password'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Incorrect password'}), 400

        token = generate_confirmation_token([email, new_password])

        if token == -1:
            log_body = f'User: {email} | Password reset token failed'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'An error occured while trying to send email.'}), 400

        confirm_url = FRONTEND_LINK + '/employee/confirm-new-password/' + token
        msg = f'Please click on the link to reset your password: {confirm_url}'
        subj = 'Confirm new password'
        employee_mail_queue([email], msg, subj)

        log_body = f'User: {email} | Password reset token sent'
        logging.info(f'{log_body}')
        return jsonify({'message': 'Password reset token sent'}), 200

    except Exception as e:
        log_body = f'Employee > Change Password > ERROR : {repr(e)}'
        logging.warning(f'User: {email} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500

@app.route('/employee/confirm-new-password/<token>')
@limiter.limit("3/second")
def employee_confirm_new_password(token):
    try:
        email, new_password = confirm_token(token)

        if not email:
            log_body = f'User: {email} | Invalid token'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'The confirmation link is invalid or has expired.'}), 400

        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        employee = Employees.query.filter_by(email=email, is_active=True).first()

        if not employee:
            log_body = f'User: {email} | Employee not found'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Employee does not exist'}), 400

        setattr(employee, 'password', hashed_password)
        db.session.commit()

        log_body = f'User: {email} | Password changed'
        logging.info(f'{log_body}')
        return jsonify({'message': 'Password reset successfully'}), 200

    except Exception as e:
        log_body = f'Employee > Confirm New Password > ERROR : {repr(e)}'
        logging.warning(f'User: {email} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500

@app.route('/employee/forgot-password', methods=['POST'])
@limiter.limit("3/second")
def employee_forgot_password():
    try:
        data = request.get_json()
        email = data['email']

        employee = Employees.query.filter_by(email=email, is_active=True).first()

        if not employee:
            log_body = f'User: {email} | Employee not found'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Employee does not exist'}), 400

        token = generate_confirmation_token(email)

        if token == -1:
            log_body = f'User: {email} | Password reset token failed'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'An error occured while trying to send email.'}), 400

        confirm_url = FRONTEND_LINK + '/employee/reset-password/' + token
        msg = f'Please click on the link to reset your password: {confirm_url}'
        subj = 'Reset password'
        employee_mail_queue([email], msg, subj)

        log_body = f'User: {email} | Password reset token sent'
        logging.info(f'{log_body}')
        return jsonify({'message': 'Email sent successfully'}), 200

    except Exception as e:
        log_body = f'Employee > Forgot Password > ERROR : {repr(e)}'
        logging.warning(f'User: {email} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500

@app.route('/employee/reset-password/<token>', methods=['POST'])
@limiter.limit("3/second")
def employee_reset_password(token):
    try:
        data = request.get_json()
        new_password = data['new_password']

        email = confirm_token(token)

        if not email:
            log_body = f'User: {email} | Invalid token'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'The confirmation link is invalid or has expired.'}), 400

        employee = Employees.query.filter_by(email=email, is_active=True).first()

        if not employee:
            log_body = f'User: {email} | Employee not found'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Employee does not exist'}), 400

        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        setattr(employee, 'password', hashed_password)
        db.session.commit()

        log_body = f'User: {email} | Password changed'
        logging.info(f'{log_body}')
        return jsonify({'message': 'Password reset successfully'}), 200

    except Exception as e:
        log_body = f'Employee > Reset Password > ERROR : {repr(e)}'
        logging.warning(f'User: {email} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500

@app.route('/employee/profile', methods=['GET'])
@limiter.limit("3/second")
@jwt_required()
def employee_profile():
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'employee':
            log_body = f'User: {jwt_identity["email"]} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Invalid user type'}), 400

        email = jwt_identity['email']
        employee = Employees.query.filter_by(email=email, is_active=True).first()   
        if not employee:
            log_body = f'User: {email} | Employee not found'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Employee does not exist'}), 400

        employee_data = {
            'id': employee.id,
            'name': employee.name,
            'surname': employee.surname,
            'email': employee.email,
            'phone': employee.phone,
            't_c': employee.t_c,
            't_c_date': employee.t_c_date,
            't_c_expire_date': employee.t_c_expire_date,
            'duration': employee.duration,
            'company_name': employee.company_name,
        }

        log_body = f'User: {email} | Employee profile'
        logging.info(f'{log_body}')
        return jsonify({'message': 'Employee profile', 'employee': employee_data}), 200

    except Exception as e:
        log_body = f'Employee > Profile > ERROR : {repr(e)}'
        logging.warning(f'User: {email} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500

@app.route('/employee/update-profile', methods=['POST'])
@limiter.limit("3/second")
@jwt_required()
def employee_update_profile():
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'employee':
            log_body = f'User: {jwt_identity["email"]} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Invalid user type'}), 400

        email = jwt_identity['email']
        employee = Employees.query.filter_by(email=email, is_active=True).first()
        if not employee:
            log_body = f'User: {email} | Employee not found'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Employee does not exist'}), 400

        data = request.get_json()

        for field in EMPLOYEE_EDIT_CHANGEABLE_FIELDS:
            if field in data:
                setattr(employee, field, data[field])

        db.session.commit()
        return jsonify({'message': 'Employee profile updated'}), 200

    except Exception as e:
        log_body = f'Employee > Update Profile > ERROR : {repr(e)}'
        logging.warning(f'User: {email} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/employee/talent-market/<int:page_no>', methods=['GET'])
@limiter.limit("3/second")
@jwt_required()
def employee_talent_get(page_no):
    try:
        jwt_identitiy = get_jwt_identity()
        user_type = jwt_identitiy['user_type']
        email = jwt_identitiy['email']

        if user_type != 'employee':
            log_body = f'User: {email} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an employee'}), 401
        
        employee = Employees.query.filter_by(email=email, is_active=True).first()

        if not employee:
            log_body = f'User: {email} | Employee not found'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Employee does not exist'}), 400

        data = request.get_json()
        
        entry_amount    = data['entry_amount']
        selected_sort   = data['selected_sort']
        selected_filter = data['selected_filter']
        is_ascending    = data['ascending']

        limit = entry_amount
        offset = (page_no - 1) * entry_amount

        number_of_students = db_filter_student_count("students", selected_filter)
        number_of_pages = math.ceil(number_of_students / entry_amount)

        students_list = db_filter_employee("students", selected_filter, selected_sort, is_ascending, limit, offset, selected_columns=SAFE_TALENT_COLUMNS)
        favourited_students = get_favourited_student_ids(employee.id)
        post_search_talent(selected_filter, employee.id)

        log_body = f'User: {email} | Talent market retrieved'
        logging.info(f'{log_body}')
        return jsonify({'students': students_list, 'number_of_pages':number_of_pages, "t_c": employee.t_c, "favourited_students": favourited_students}), 200
        
    except Exception as e:
        log_body = f'Employee > Talent Market > ERROR : {repr(e)}'
        logging.warning(f'User: {email} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500

@app.route('/employee/add-favourite', methods=['POST'])
@limiter.limit("3/second")
@jwt_required()
def employee_add_favourite():
    try:
        jwt_identitiy = get_jwt_identity()
        user_type = jwt_identitiy['user_type']
        email = jwt_identitiy['email']

        if user_type != 'employee':
            log_body = f'User: {email} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an employee'}), 401
        
        employee = Employees.query.filter_by(email=email, is_active=True).first()

        if not employee:
            log_body = f'User: {email} | Employee not found'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Employee does not exist'}), 400

        data = request.get_json()
        student_id = data['id']
        student = Students.query.filter_by(id=student_id, is_active=True).first()

        if not student:
            log_body = f'User: {email} | Student not found'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Student does not exist'}), 400

        employee_id = employee.id
        company_id = employee.company_ref.id

        old_fav = Favourites.query.filter_by(student_id=student_id, employee_id=employee_id, company_id=company_id, is_active=True).first()

        if old_fav:
            log_body = f'User: {email} | Student already favourited'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Student is already in favourites'}), 400

        favourite = Favourites(student_id, company_id, employee_id)
        db.session.add(favourite)
        db.session.commit()

        log_body = f'User: {email} | Student favourited'
        logging.info(f'{log_body}')
        return jsonify({'message': 'Student added to favourites'}), 200

    except Exception as e:
        log_body = f'Employee > Add Favourite > ERROR : {repr(e)}'
        logging.warning(f'User: {email} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500

@app.route('/employee/remove-favourite', methods=['POST'])
@limiter.limit("3/second")
@jwt_required()
def employee_remove_favourite():
    try:
        jwt_identitiy = get_jwt_identity()
        user_type = jwt_identitiy['user_type']
        email = jwt_identitiy['email']

        if user_type != 'employee':
            log_body = f'User: {email} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an employee'}), 401
        
        employee = Employees.query.filter_by(email=email, is_active=True).first()

        if not employee:
            log_body = f'User: {email} | Employee not found'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Employee does not exist'}), 400

        data = request.get_json()
        student_id = data['id']
        student = Students.query.filter_by(id=student_id, is_active=True).first()

        if not student:
            log_body = f'User: {email} | Student not found'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Student does not exist'}), 400

        employee_id = employee.id
        company_id = employee.company_ref.id

        favourite = Favourites.query.filter_by(student_id=student_id, employee_id=employee_id, company_id=company_id, is_active=True).first()
        if not favourite:
            log_body = f'User: {email} | Student not favourited'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Student is not in favourites'}), 400

        db.session.delete(favourite)
        db.session.commit()

        log_body = f'User: {email} | Student removed from favourites'
        logging.info(f'{log_body}')
        return jsonify({'message': 'Student removed from favourites'}), 200

    except Exception as e:
        log_body = f'Employee > Remove Favourite > ERROR : {repr(e)}'
        logging.warning(f'User: {email} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500

@app.route('/employee/my-favourites', methods=['GET'])
@limiter.limit("3/second")
@jwt_required()
def employee_my_favourites():
    try:
        jwt_identitiy = get_jwt_identity()
        user_type = jwt_identitiy['user_type']
        email = jwt_identitiy['email']

        if user_type != 'employee':
            log_body = f'User: {email} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an employee'}), 401

        employee = Employees.query.filter_by(email=email, is_active=True).first()

        if not employee:
            log_body = f'User: {email} | Employee not found'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Employee does not exist'}), 400

        students_list = get_my_favourites(employee.id, employee.t_c)

        log_body = f'User: {email} | My favourites'
        logging.info(f'{log_body}')
        return jsonify({'students': students_list, 't_c': employee.t_c}), 200
    except Exception as e:
        log_body = f'Employee > My Favourites > ERROR : {repr(e)}'
        logging.warning(f'User: {email} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/employee/student-profile/<int:student_id>', methods=['GET'])
@limiter.limit("3/second")
@jwt_required()
def employee_student_profile(student_id):
    try:
        jwt_identitiy = get_jwt_identity()
        user_type = jwt_identitiy['user_type']
        email = jwt_identitiy['email']

        if user_type != 'employee':
            log_body = f'User: {email} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an employee'}), 401
        
        employee = Employees.query.filter_by(email=email, is_active=True).first()

        if not employee:
            log_body = f'User: {email} | Employee not found'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Employee does not exist'}), 400

        student = Students.query.filter_by(id=student_id, is_active=True).first()
        if not student:
            log_body = f'User: {email} | Student not found'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Student does not exist'}), 400

        student_info = get_specific_data(student, select_std(employee.t_c), get_raw=True, direct_data=True)

        log_body = f'User: {email} | Student profile'
        logging.info(f'{log_body}')
        return jsonify({'student': student_info, 't_c': employee.t_c}), 200

    except Exception as e:
        log_body = f'Employee > Student Profile > ERROR : {repr(e)}'
        logging.warning(f'User: {email} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500

@app.route('/employee/t-c', methods=['GET'])
@limiter.limit("3/second")
@jwt_required()
def employee_t_c():
    try:
        jwt_identitiy = get_jwt_identity()
        user_type = jwt_identitiy['user_type']
        email = jwt_identitiy['email']

        if user_type != 'employee':
            log_body = f'User: {email} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an employee'}), 401
        
        employee = Employees.query.filter_by(email=email, is_active=True).first()
        if not employee:
            log_body = f'User: {email} | Employee not found'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Employee does not exist'}), 400

        if employee.t_c:
            remaining_t_c = employee.t_c_expire_date - datetime.now()
            
            remaining_total_seconds = int(remaining_t_c.total_seconds())
            remaining_months = int(remaining_total_seconds / (30*24*60*60))
            remaining_days = int((remaining_total_seconds % (30*24*60*60)) / (24*60*60))
            remaining_hours = int((remaining_total_seconds % (24*60*60)) / (60*60))
            remaining_minutes = int((remaining_total_seconds % (60*60)) / 60)
            remaining_seconds = int(remaining_total_seconds % 60)

            remaining = [remaining_months, remaining_days, remaining_hours, remaining_minutes, remaining_seconds]

            log_body = f'User: {email} | T-C'
            logging.info(f'{log_body}')
            return jsonify({'t_c': employee.t_c, 't_c_date': employee.t_c_date, 't_c_expire_date': employee.t_c_expire_date, 'remaining_t_c': remaining}), 200
        
        log_body = f'User: {email} | T-C'
        logging.info(f'{log_body}')
        return jsonify({'t_c': employee.t_c}), 200

    except Exception as e:
        log_body = f'Employee > T&C > ERROR : {repr(e)}'
        logging.warning(f'User: {email} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500

@app.route('/employee/t-c', methods=['POST'])
@limiter.limit("3/second")
@jwt_required()
def employee_t_c_update():
    try:
        jwt_identitiy = get_jwt_identity()
        user_type = jwt_identitiy['user_type']
        email = jwt_identitiy['email']

        if user_type != 'employee':
            log_body = f'User: {email} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an employee'}), 401
        
        employee = Employees.query.filter_by(email=email, is_active=True).first()

        if not employee:
            log_body = f'User: {email} | Employee not found'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Employee does not exist'}), 400

        if employee.t_c:
            log_body = f'User: {email} | T-C already exists'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You have already accepted the T&C'}), 400

        setattr(employee, 't_c', True)
        setattr(employee, 't_c_date', datetime.now())
        setattr(employee, 't_c_expire_date', datetime.now() + timedelta(6*30))

        db.session.commit()

        log_body = f'User: {email} | T-C'
        logging.info(f'{log_body}')
        return jsonify({'message': 'T&C updated'}), 200

    except Exception as e:
        log_body = f'Employee > T&C > ERROR : {repr(e)}'
        logging.warning(f'User: {email} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


# ========================================================================================
#   End of EMPLOYEE Routes
# ========================================================================================


# ========================================================================================
#   ADMINISTRATOR Routes
# ========================================================================================
@app.route('/admin/login', methods=['POST'])
@limiter.limit("3/second")
def administrator_login():
    try:
        data = request.get_json()
        email = data['email']
        password = data['password']

        admin = None

        try:
            with open('admins/admin1.json', 'r') as j:
                admin = json.load(j)
        except Exception as e:
            log_body = f'Admin > Login > ERROR : {repr(e)}'
            logging.warning(f'IP: {request.remote_addr} | {log_body}')
            return jsonify({'message': 'Something went wrong'}), 500

        admin = dict(admin)

        if email != admin['email'] or admin['password'] != password:
            log_body = f'Admin > Login > ERROR : Invalid credentials'
            logging.warning(f'IP: {request.remote_addr} | {log_body}')
            return jsonify({'message': 'Incorrect password or email'}), 400

        token_identity = {'user_type': 'admin', 'login_date': datetime.now().timestamp()}
        access_token = create_access_token(identity=token_identity)
        
        return jsonify({'access_token': access_token}), 200

    except Exception as e:
        log_body = f'Admin > Login > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/admin/company', methods=['GET'])
@limiter.limit("3/second")
@jwt_required()
def admin_test_companies():
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']
        if user_type != 'admin':
            log_body = f'IP: {request.remote_addr} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an administrator'}), 401

        try:
            companies = get_companies()
            log_body = f'IP: {request.remote_addr} | Companies'
            logging.info(f'{log_body}')
            return jsonify({'companies': companies}), 200

        except Exception as e:
            log_body = f'Admin > Companies > Request Operation > ERROR : {repr(e)}'
            logging.warning(f'IP: {request.remote_addr} | {log_body}')
            return jsonify({'message': 'Something went wrong'}), 500

    except Exception as e:
        log_body = f'Admin > Companies > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/admin/company/register', methods=['POST'])
@limiter.limit("3/second")
@jwt_required()
def company_register():
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            log_body = f'IP: {request.remote_addr} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an administrator'}), 401

        try:
            data = request.get_json()
            company_name = data['company_name']
            special_id = random_id_generator(8)
            company_users = data['company_users']

            old_company = Companies.query.filter_by(company_name=company_name, is_active=True).first()
            if old_company:
                log_body = f'IP: {request.remote_addr} | Company already exists'
                logging.warning(f'{log_body}')
                return jsonify({'message': 'Company already exists'}), 400

            # Try for a few times to generate a special id
            while True:
                if Companies.query.filter_by(special_id=special_id).first():
                    special_id = random_id_generator(8)
                else:
                    break

            for em in company_users:
                if Employees.query.filter_by(email=em, is_active=True).first():
                    company_users.remove(em)

            company = Companies(company_name, special_id, company_users)
            db.session.add(company)
            db.session.commit()

            if company_users:
                # Send mails to employees so they know they can register
                register_url = FRONTEND_LINK + '/employee/register'
                subj = 'Dear {} Employee'.format(company.company_name.upper())
                msg = 'You can register at {} with this id: {}'.format(register_url, company.special_id)
                employee_mail_queue(company_users, msg, subj)
            
            log_body = f'IP: {request.remote_addr} | Company registered'
            logging.info(f'{log_body}')
            return jsonify({'message': 'Company created successfully'}), 201
        except Exception as e:
            log_body = f'Admin > Company Register > Request Operation > ERROR : {repr(e)}'
            logging.warning(f'IP: {request.remote_addr} | {log_body}')
            return jsonify({'message': 'Something went wrong'}), 500

    except Exception as e:
        log_body = f'Admin > Company Register > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500

# Admin removes a company from DB
@app.route('/admin/company/remove', methods=['POST'])
@limiter.limit("3/second")
@jwt_required()
def company_remove():
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            log_body = f'IP: {request.remote_addr} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an administrator'}), 401

        try:
            data = request.get_json()
            company_id = data['id']

            company = Companies.query.filter_by(id=company_id, is_active=True).first()

            if not company:
                log_body = f'IP: {request.remote_addr} | Company does not exist'
                logging.warning(f'{log_body}')
                return jsonify({'message': 'Company does not exist'}), 400

            update_is_active_company(company_id)
            
            log_body = f'IP: {request.remote_addr} | Company removed'
            logging.info(f'{log_body}')
            return jsonify({'message': 'Company removed successfully'}), 200
        except Exception as e:
            log_body = f'Admin > Remove Company > Request Operation > ERROR : {repr(e)}'
            logging.warning(f'IP: {request.remote_addr} | {log_body}')
            return jsonify({'message': 'Something went wrong'}), 500

    except Exception as e:
        log_body = f'Admin > Remove Company > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500

# Admin gets specific company's data
@app.route('/admin/company/<int:company_id>', methods=['GET'])
@limiter.limit("3/second")
@jwt_required()
def get_company(company_id):
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            log_body = f'IP: {request.remote_addr} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an administrator'}), 401

        try:
            company = Companies.query.filter_by(id=company_id, is_active=True).first()
            if not company:
                log_body = f'IP: {request.remote_addr} | Company does not exist'
                logging.warning(f'{log_body}')
                return jsonify({'message': 'Company does not exist'}), 400

            log_body = f'IP: {request.remote_addr} | Company data retrieved'
            logging.info(f'{log_body}')
            return jsonify(get_specific_data(company, DC_AD_COMPANIES, get_raw=True)), 200

        except Exception as e:
            log_body = f'Admin > Get Company > Request Operation > ERROR : {repr(e)}'
            logging.warning(f'IP: {request.remote_addr} | {log_body}')
            return jsonify({'message': 'Something went wrong'}), 500

    except Exception as e:
        log_body = f'Admin > Get Company > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/admin/company/<int:company_id>/edit', methods=['POST'])
@limiter.limit("3/second")
@jwt_required()
def edit_company(company_id):
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            log_body = f'IP: {request.remote_addr} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an administrator'}), 401

        try:
            company = Companies.query.filter_by(id=company_id, is_active=True).first()
            if not company:
                log_body = f'IP: {request.remote_addr} | Company does not exist'
                logging.warning(f'{log_body}')
                return jsonify({'message': 'Company does not exist'}), 400

            data = request.get_json()

            new_company_name = data['company_name']
            update_company_name(new_company_name, company.company_name)
            
            log_body = f'IP: {request.remote_addr} | Company data updated'
            logging.info(f'{log_body}')
            return jsonify({'message': 'Company updated successfully. '}), 200

        except Exception as e:
            log_body = f'Admin > Company Edit > Request Operation > ERROR : {repr(e)}'
            logging.warning(f'IP: {request.remote_addr} | {log_body}')
            return jsonify({'message': 'Something went wrong'}), 500

    except Exception as e:
        log_body = f'Admin > Company Edit > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/admin/company/<int:company_id>/add-employee', methods=['POST'])
@limiter.limit("3/second")
@jwt_required()
def company_add_user(company_id):
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            log_body = f'IP: {request.remote_addr} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an administrator'}), 401

        data = request.get_json()
        new_employees = data['company_users']
        
        try:
            company = Companies.query.filter_by(id=company_id, is_active=True).first()
            if not company:
                log_body = f'IP: {request.remote_addr} | Company does not exist'
                logging.warning(f'{log_body}')
                return jsonify({'message': 'Company does not exist'}), 400

            current_employees = company.company_users
            employees_to_add = []
            for em in new_employees:
                if Employees.query.filter_by(email=em, is_active=True).first():
                    continue

                if em not in current_employees:
                    employees_to_add.append(em)
            
            if not employees_to_add:
                log_body = f'IP: {request.remote_addr} | No new employees to add'
                logging.warning(f'{log_body}')
                return jsonify({'message': 'No new employees to add'}), 400

            final_employees = company.company_users + employees_to_add
            
            setattr(company, 'company_users', final_employees)
            db.session.commit()

            # Send mails to employees so they know they can register
            register_url = FRONTEND_LINK + '/employee/register'
            subj = 'Dear {} Employee'.format(company.company_name.upper())
            msg = f'You can register at {register_url} with this id: {company.special_id}'
            employee_mail_queue(employees_to_add, subj, msg)

            log_body = f'IP: {request.remote_addr} | Employees added to company'
            logging.info(f'{log_body}')
            return jsonify({'message': 'Employees updated succesfully. Added: ' + str(final_employees)}), 200
        except Exception as e:
            log_body = f'Admin > Company Add Employee > Request Operation > ERROR : {repr(e)}'
            logging.warning(f'IP: {request.remote_addr} | {log_body}')
            return jsonify({'message': 'Something went wrong in request operations'}), 500

    except Exception as e:
        log_body = f'Admin > Company Add Employee > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


# Admin removes an employee of a company
@app.route('/admin/company/<int:company_id>/remove-employee', methods=['POST'])
@limiter.limit("3/second")
@jwt_required()
def company_remove_user(company_id):
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            log_body = f'IP: {request.remote_addr} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an administrator'}), 401

        data = request.get_json()
        employee_to_remove = data['employee_mail']
        
        try:
            company = Companies.query.filter_by(id=company_id, is_active=True).first()
            current_employees = company.company_users[:]

            if not current_employees:
                log_body = f'IP: {request.remote_addr} | Company does not have employees'
                logging.warning(f'{log_body}')
                return jsonify({'message': 'Company does not have any employees'}), 400

            if employee_to_remove in current_employees:
                current_employees.remove(employee_to_remove)
                employee = Employees.query.filter_by(email=employee_to_remove, is_active=True).first()
                if employee:
                    update_is_activate_employees([employee.id])
                
            setattr(company, 'company_users', current_employees)
            db.session.commit()

            log_body = f'IP: {request.remote_addr} | Employee removed from company'
            logging.info(f'{log_body}')
            return jsonify({'message': 'Employee removed succesfully'}), 200
        except Exception as e:
            log_body = f'Admin > Company Remove Employee > Request Operation > ERROR : {repr(e)}'
            logging.warning(f'IP: {request.remote_addr} | {log_body}')
            return jsonify({'message': 'Something went wrong in request operations'}), 500

    except Exception as e:
        log_body = f'Admin > Company Remove Employee > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/admin/employee/<int:page_no>', methods=['GET'])
@limiter.limit("3/second")
@jwt_required()
def admin_employees(page_no):
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            log_body = f'IP: {request.remote_addr} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an administrator'}), 401

        if page_no < 1:
            log_body = f'IP: {request.remote_addr} | Invalid page number'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Page number must at least be 1'}), 400

        data = request.get_json()
        
        entry_amount    = data['entry_amount']
        selected_sort   = data['selected_sort']
        selected_filter = data['selected_filter']
        is_ascending       = data['ascending']

        limit = entry_amount
        offset = (page_no - 1) * entry_amount

        number_of_employees = db_filter_admin_count("employees", selected_filter)
        number_of_pages = math.ceil(number_of_employees / entry_amount)

        employees = db_filter_admin('employees', selected_filter, selected_sort, is_ascending, limit, offset)
        fav_amounts = get_fav_amount(is_employee=True)

        log_body = f'IP: {request.remote_addr} | Employees retrieved'
        logging.info(f'{log_body}')
        return jsonify({'max_pages': number_of_pages, 'employees': employees, 'fav_amounts': fav_amounts}), 200
    except Exception as e:
        log_body = f'Admin > Employees > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500

@app.route('/admin/employee/get/<int:employee_id>', methods=['GET'])
@limiter.limit("3/second")
@jwt_required()
def admin_employee_get(employee_id):
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            log_body = f'IP: {request.remote_addr} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an administrator'}), 401

        employee = Employees.query.filter_by(id=employee_id, is_active=True).first()

        if not employee:
            log_body = f'IP: {request.remote_addr} | Employee not found'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Employee does not exist'}), 400

        employee = employee.to_dict()
        fav_amount = db_count_student_fav(employee['id'])

        log_body = f'IP: {request.remote_addr} | Employee retrieved'
        logging.info(f'{log_body}')
        return jsonify({**employee, "fav_amount": fav_amount}), 200
    except Exception as e:
        log_body = f'Admin > Employee Get > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/admin/employee/edit/<int:employee_id>', methods=['POST'])
@limiter.limit("3/second")
@jwt_required()
def admin_employee_edit(employee_id):
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            log_body = f'IP: {request.remote_addr} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an administrator'}), 401

        data = request.get_json()['values']

        if 'password' in data.keys():
            del data['password']
        
        if 'company' in data.keys():
            del data['company']
        
        if 'company_name' in data.keys():
            del data['company_name']

        try:
            employee = Employees.query.filter_by(id=employee_id, is_active=True).first()
            if not employee:
                log_body = f'IP: {request.remote_addr} | Employee not found'
                logging.warning(f'{log_body}')
                return jsonify({'message': 'Employee does not exist'}), 400

            for key, value in data.items():
                setattr(employee, key, value)
                if key == 't_c':
                    if value:
                        setattr(employee, 't_c_date', datetime.now())
                        setattr(employee, 't_c_expire_date', datetime.now() + timedelta(6*30))
                    else:
                        setattr(employee, 't_c_date', None)
                        setattr(employee, 't_c_expire_date', None)
            db.session.commit()
            
        except Exception as e:
            log_body = f'Admin > Employee Edit > Request Operation > ERROR : {repr(e)}'
            logging.warning(f'IP: {request.remote_addr} | {log_body}')
            return jsonify({'message': 'Something went wrong in request operations'}), 500

        log_body = f'IP: {request.remote_addr} | Employee edited'
        logging.info(f'{log_body}')
        return jsonify({'message': 'Employee edited succesfully'}), 200
    except Exception as e:
        log_body = f'Admin > Employee Edit > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/admin/employee/favourites/<int:employee_id>', methods=['GET'])
@limiter.limit("3/second")
@jwt_required()
def admin_employee_favourites(employee_id):
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            log_body = f'IP: {request.remote_addr} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an administrator'}), 401

        employee = Employees.query.filter_by(id=employee_id, is_active=True).first()

        if not employee:
            log_body = f'IP: {request.remote_addr} | Employee not found'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Employee does not exist'}), 400

        favourited_students = db_get_student_for_fav(employee.id)

        log_body = f'IP: {request.remote_addr} | Employee favourites retrieved'
        logging.info(f'{log_body}')
        return jsonify({'favourites': favourited_students}), 200
    except Exception as e:
        log_body = f'Admin > Employee Favourites > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/admin/employee/multiple-remove', methods=['POST'])
@limiter.limit("3/second")
@jwt_required()
def admin_employees_multiple_remove():
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            log_body = f'IP: {request.remote_addr} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an administrator'}), 401

        data = request.get_json()
        employees_to_remove = data['removed_users']

        try:
            update_is_activate_employees(employees_to_remove)

            for id in employees_to_remove:
                try:
                    employee = Employees.query.filter_by(id=id, is_active=True).first()
                    company = Companies.query.filter_by(id=employee.company_id, is_active=True).first()

                    company_users = company.company_users.remove(employee.email)
                    setattr(company, 'company_users', company_users)
                except:
                    pass

            db.session.commit()
                
            log_body = f'IP: {request.remote_addr} | Employees removed'
            logging.info(f'{log_body}')
            return jsonify({'message': 'Employees removed succesfully.'}), 200

        except Exception as e:
            log_body = f'Admin > Employees > Multiple Remove > Request Operation > ERROR : {repr(e)}'
            logging.warning(f'IP: {request.remote_addr} | {log_body}')
            return jsonify({'message': 'Something went wrong in request operations'}), 500

    except Exception as e:
        log_body = f'Admin > Employees > Multiple Remove > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/admin/student/<int:page_no>', methods=['GET'])
@limiter.limit("3/second")
@jwt_required()
def admin_students(page_no):
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            log_body = f'IP: {request.remote_addr} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an administrator'}), 401

        if page_no < 1:
            log_body = f'IP: {request.remote_addr} | Invalid page number'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Page number must at least be 1'}), 400

        data = request.get_json()

        entry_amount    = data['entry_amount']
        selected_sort   = data['selected_sort']
        selected_filter = data['selected_filter']
        is_ascending       = data['ascending']

        limit = entry_amount
        offset = (page_no - 1) * entry_amount

        number_of_students = db_filter_admin_count("students", selected_filter)
        number_of_pages = math.ceil(number_of_students / entry_amount)

        students = db_filter_admin('students', selected_filter, selected_sort, is_ascending, limit, offset)
        fav_amounts = get_fav_amount(is_student=True)

        log_body = f'IP: {request.remote_addr} | Students retrieved'
        logging.info(f'{log_body}')
        return jsonify({'max_pages': number_of_pages, 'students': students, 'fav_amounts': fav_amounts}), 200
    except Exception as e:
        log_body = f'Admin > Students > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/admin/student/get/<int:student_id>', methods=['GET'])
@limiter.limit("3/second")
@jwt_required()
def admin_student_get(student_id):
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            log_body = f'IP: {request.remote_addr} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an administrator'}), 401

        student = Students.query.filter_by(id=student_id, is_active=True).first()

        if not student:
            log_body = f'IP: {request.remote_addr} | Student not found'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Student does not exist'}), 400

        student = student.to_dict()
        fav_amount = db_count_employee_fav(student['id'])

        log_body = f'IP: {request.remote_addr} | Student retrieved'
        logging.info(f'{log_body}')
        return jsonify({**student, "fav_amount": fav_amount}), 200
    except Exception as e:
        log_body = f'Admin > Student Get > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/admin/student/edit/<int:student_id>', methods=['POST'])
@limiter.limit("3/second")
@jwt_required()
def admin_student_edit(student_id):
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            log_body = f'IP: {request.remote_addr} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an administrator'}), 401

        data = request.get_json()

        if 'job_find_time' in data:
            del data['job_find_time']

        if 'password' in data.keys():
            del data['password']

        try:
            student = Students.query.filter_by(id=student_id, is_active=True).first()
            if not student:
                log_body = f'IP: {request.remote_addr} | Student not found'
                logging.warning(f'{log_body}')
                return jsonify({'message': 'Student does not exist'}), 400

            for key, value in data.items():
                setattr(student, key, value)
            db.session.commit()
        except Exception as e:
            log_body = f'Admin > Student Edit > Request Operation > ERROR : {repr(e)}'
            logging.warning(f'IP: {request.remote_addr} | {log_body}')
            return jsonify({'message': 'Something went wrong in request operations'}), 500

        log_body = f'IP: {request.remote_addr} | Student edited'
        logging.info(f'{log_body}')
        return jsonify({'message': 'Student edited succesfully'}), 200
    except Exception as e:
        log_body = f'Admin > Student Edit > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/admin/student/favourites/<int:student_id>', methods=['GET'])
@limiter.limit("3/second")
@jwt_required()
def admin_student_favorite(student_id):
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            log_body = f'IP: {request.remote_addr} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an administrator'}), 401

        student = Students.query.filter_by(id=student_id, is_active=True).first()

        if not student:
            log_body = f'IP: {request.remote_addr} | Student not found'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Student does not exist'}), 400

        favourited_employees = db_get_employee_for_fav(student.id)
        
        log_body = f'IP: {request.remote_addr} | Student favourites retrieved'
        logging.info(f'{log_body}')
        return jsonify({'favourites': favourited_employees}), 200
    except Exception as e:
        log_body = f'Admin > Student Favorite > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500

# Admin - Multiple remove students
@app.route('/admin/student/multiple-remove', methods=['POST'])
@limiter.limit("3/second")
@jwt_required()
def admin_students_multiple_remove():
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            log_body = f'IP: {request.remote_addr} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an administrator'}), 401

        data = request.get_json()
        students_to_remove = data['removed_users']

        try:
            update_is_activate_students(students_to_remove)
            log_body = f'IP: {request.remote_addr} | Students removed'
            logging.info(f'{log_body}')
            return jsonify({'message': 'Students removed succesfully.'}), 200

        except Exception as e:
            log_body = f'Admin > Students > Multiple Remove > Request Operation > ERROR : {repr(e)}'
            logging.warning(f'IP: {request.remote_addr} | {log_body}')
            return jsonify({'message': 'Something went wrong in request operations'}), 500

    except Exception as e:
        log_body = f'Admin > Students > Multiple Remove > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/admin/program/create', methods=['POST'])
@limiter.limit("3/second")
@jwt_required()
def admin_create_program():
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            log_body = f'IP: {request.remote_addr} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an administrator'}), 401

        data = request.get_json()
        program_name = data['program_name']
        program_code = data['program_code']

        if Programs.query.filter_by(program_code=program_code, program_name=program_name).first():
            log_body = f'IP: {request.remote_addr} | Program already exists'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Program already exists'}), 400

        program = Programs(program_name, program_code)
        db.session.add(program)
        db.session.commit()

        log_body = f'IP: {request.remote_addr} | Program created'
        logging.info(f'{log_body}')
        return jsonify({'message': 'Program created succesfully'}), 200

    except Exception as e:
        log_body = f'Admin > Programs > Create > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/admin/program/edit/<id>', methods=['POST'])
@limiter.limit("3/second")
@jwt_required()
def admin_program_edit(id):
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            log_body = f'IP: {request.remote_addr} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an administrator'}), 401

        data = request.get_json()

        new_program_name = data['program_name']
        new_program_code = data['program_code']

        program = Programs.query.filter_by(id=id).first()
        if not program:
            log_body = f'IP: {request.remote_addr} | Program not found'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Program does not exist'}), 400

        if program.program_code == new_program_code and program.program_name == new_program_name:
            log_body = f'IP: {request.remote_addr} | Program not changed'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Same values given.'}), 400

        if Programs.query.filter_by(program_code=new_program_code).filter_by(program_name=new_program_name).first():
            log_body = f'IP: {request.remote_addr} | Program already exists'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'Program already exists'}), 400

        setattr(program, 'program_name', new_program_name)
        setattr(program, 'program_code', new_program_code)
        db.session.commit()

        log_body = f'IP: {request.remote_addr} | Program edited'
        logging.info(f'{log_body}')
        return jsonify({'message': 'Program edited succesfully'}), 200
    except Exception as e:
        log_body = f'Admin > Program Edit > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/admin/program/invite', methods=['POST'])
@limiter.limit("3/second")
@jwt_required()
def admin_program_invite_students():
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            log_body = f'IP: {request.remote_addr} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an administrator'}), 401

        data = request.get_json()
        program_name = data['inviteProgramName']
        program_code = data['inviteProgramCode']
        students_to_invite = data['emails']

        if not students_to_invite:
            log_body = f'IP: {request.remote_addr} | No students to invite'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'No emails received'}), 400

        students_invited = []

        try:
            program = Programs.query.filter_by(program_name=program_name, program_code=program_code).first()
            if not program:
                log_body = f'IP: {request.remote_addr} | Program not found'
                logging.warning(f'{log_body}')
                return jsonify({'message': 'Program does not exist'}), 400

            register_url = FRONTEND_LINK + '/student/register'

            for st_mail in students_to_invite:
                student = Students.query.filter_by(email=st_mail, is_active=True).first()

                if student:
                    print(f'Following email is already in Students table: {st_mail}')
                    try:
                        school_programs = student.school_programs

                        temp_boolean = False
                        for sp in school_programs:
                            if sp["program_name"] == program_name and sp["program_code"] == program_code:
                                print(f'Following student is already in this program: {st_mail}')
                                temp_boolean = True
                        
                        if not temp_boolean:
                            program_to_add = {
                                "github_link": "",
                                "program_name": program_name,
                                "program_code": program_code,
                                "summary": "",
                                "video_link": ""
                            }
                            school_programs = school_programs + [program_to_add]
                            setattr(student, 'school_programs', school_programs)
                            db.session.commit()

                            subj = 'New UP School Program'
                            msg = f'You are added to new UP School Program: {program_name} \nPlease update your profile informations.'
                            student_mail_queue([student.email], msg, subj)
                            setattr(student, 'profile_complete', False)

                    except Exception as e:
                        log_body = f'Admin > Program Invite > Student > ERROR : {repr(e)}'
                        logging.warning(f'IP: {request.remote_addr} | {log_body}')
                        return jsonify({'message': 'Something went wrong in student operations'}), 500
                    continue

                temp = Temps.query.filter_by(email=st_mail).first()
                if temp:
                    print(f'Following email is already in Temps table: {st_mail}')

                    try:
                        program_names = temp.program_names
                        program_codes = temp.program_codes

                        temp_boolean = True
                        for i in range(len(program_names)):
                            if program_names[i] == program_name and program_codes[i] == program_code:
                                temp_boolean = False
                                break

                        if temp_boolean:
                            program_names = program_names + [program_name]
                            program_codes = program_codes + [program_code]
                            setattr(temp, 'program_names', program_names)
                            setattr(temp, 'program_codes', program_codes)
                            db.session.commit()

                            subj = 'Dear {} Graduate'.format(program_name)
                            msg = 'You can register with the following link: {} .'.format(register_url)
                            student_mail_queue([st_mail], msg, subj)
                    except Exception as e:
                        log_body = f'Admin > Program Invite > Invite Students > ERROR : {repr(e)}'
                        logging.warning(f'IP: {request.remote_addr} | {log_body}')
                        return jsonify({'message': 'Something went wrong in request operations'}), 500
                    continue
                
                try:
                    temp_student = Temps(st_mail, [program_name], [program_code])
                    db.session.add(temp_student)

                    subj = 'Dear {} Graduate'.format(program_name)
                    msg = 'You can register with the following link: {} .'.format(register_url)
                    student_mail_queue([st_mail], msg, subj)

                except Exception as e:
                    print('Error:', e)
            
            db.session.commit()
            
        except Exception as e:
            log_body = f'Admin > Program > Add Students > Request Operation > ERROR : {repr(e)}'
            logging.warning(f'IP: {request.remote_addr} | {log_body}')
            return jsonify({'message': 'Something went wrong in request operations'}), 500
        
        log_body = f'IP: {request.remote_addr} | Students invited'
        logging.info(f'{log_body}')
        return jsonify({'message': 'Students invited succesfully: ' + str(students_invited)}), 200
    except Exception as e:
        log_body = f'Admin > Program > Add Students > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


# get programs
@app.route('/admin/program', methods=['GET'])
@limiter.limit("3/second")
@jwt_required()
def admin_get_programs():
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            log_body = f'IP: {request.remote_addr} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an administrator'}), 401

        programs_list = get_programs()
        
        log_body = f'IP: {request.remote_addr} | Programs list'
        logging.info(f'{log_body}')
        return jsonify({'programs': programs_list}), 200
    except Exception as e:
        log_body = f'Admin > Program > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500

@app.route('/admin/program/remove', methods=['POST'])
@limiter.limit("3/second")
@jwt_required()
def admin_program_remove():
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            log_body = f'IP: {request.remote_addr} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an administrator'}), 401

        data = request.get_json()
        program_name = data['program_name']
        program_code = data['program_code']

        try:
            program = Programs.query.filter_by(program_name=program_name, program_code=program_code).first()
            if not program:
                log_body = f'IP: {request.remote_addr} | Program not found'
                logging.warning(f'{log_body}')
                return jsonify({'message': 'Program does not exist'}), 400

            db.session.delete(program)
            db.session.commit()
        except Exception as e:
            log_body = f'Admin > Program > Remove > Request Operation > ERROR : {repr(e)}'
            logging.warning(f'IP: {request.remote_addr} | {log_body}')
            return jsonify({'message': 'Something went wrong in request operations'}), 500

        log_body = f'IP: {request.remote_addr} | Program removed'
        logging.info(f'{log_body}')
        return jsonify({'message': 'Program removed succesfully'}), 200
    except Exception as e:
        log_body = f'Admin > Program > Remove > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/admin/data', methods=['GET'])
@limiter.limit("3/second")
@jwt_required()
def admin_data():
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            log_body = f'IP: {request.remote_addr} | Invalid user type'
            logging.warning(f'{log_body}')
            return jsonify({'message': 'You are not an administrator'}), 401

        students_table_count  = general_select_count('students')
        temps_table_count     = general_select_count('temps')
        employees_table_count = general_select_count('employees')
        
        # Ortalama İş Bulma Süresi Grafiği
        avg_job_find_time = 158.91

        # Student data
        student_grad_total      = students_table_count + temps_table_count
        student_signup_total    = students_table_count
        student_completed_total = general_select_count('students', {'profile_complete': "True"})

        # Employee data
        employee_invite_total   = company_invite_total()
        employee_signup_total   = employees_table_count
        employee_tc_total       = general_select_count('employees', {'t_c': "True"})

        grad_profile = {
            'grad_total': student_grad_total,
            'signup_total': student_signup_total,
            'completed_total' : student_completed_total
        }

        account_signup = {
            'invite_total' : employee_invite_total,
            'signup_total' : employee_signup_total,
            'total_tc' : employee_tc_total
        }

        company_signup = company_based_employee_rates()
        employment_rate = get_employment_rate()

        grad_profile_programs = {
            'data-science' : {
                'grad_total': 140,
                'signup_total': 60,
                'completed_total' : 30
            },
            'frontend' : {
                'grad_total': 20,
                'signup_total': 37,
                'completed_total' : 21
            },
            'backend' : {
                'grad_total': 30,
                'signup_total': 31,
                'completed_total' : 26
            },
            'fullstack' : {
                'grad_total': 90,
                'signup_total': 39,
                'completed_total' : 24
            }
        }

        
        job_title_search = search_statistics('job_title')
        highest_education_grad_date_search = search_statistics('highest_education_grad_date')
        highest_education_search = search_statistics('highest_education')
        comp_skills_search = search_statistics('comp_skills')
        languages_search = search_statistics('languages')
        workplace_type_search = search_statistics('workplace_type')
        onsite_city_search = search_statistics('onsite_city')

        filter_top = {
            'job_title' : job_title_search,
            'highest_education_grad_date' : highest_education_grad_date_search,
            'highest_education' : highest_education_search,
            'comp_skills' : comp_skills_search,
            'languages' : languages_search,
            'workplace_type' : workplace_type_search,
            'onsite_city' : onsite_city_search
        }

        data = {
            'grad_profile': grad_profile,
            'company_signup': company_signup,
            'account_signup': account_signup,
            'employment_rate' : employment_rate,
            'grad_profile_programs' : grad_profile_programs,
            'avg_job_find_time' : avg_job_find_time,
            'filter_top5' : filter_top
        }

        log_body = f'IP: {request.remote_addr} | Data retrieved'
        logging.info(f'{log_body}')
        return jsonify(**data), 200
    except Exception as e:
        log_body = f'Admin > Data > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500
    

# ========================================================================================
#   End of ADMINISTRATOR Routes
# ========================================================================================


if __name__ == '__main__':
    app.run(debug=True)