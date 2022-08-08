from math import ceil
from flask import request, jsonify, url_for
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity
from datetime import datetime, timedelta
import json

from itsdangerous import URLSafeTimedSerializer

from scripts.util import app, bcrypt, db_filter_employee, jwt, db, engine, get_specific_data, update_table_data, update_profile_data, random_id_generator, logging, db_filter_admin
from scripts.util import FRONTEND_LINK, DC_AD_STUDENT, DC_AD_COMPANIES, DC_AD_EMPLOYEES, DC_ST_GENERAL, DC_ST_ACTIVITIES, DC_ST_HARDSKILLS, DC_ST_JOB
from scripts.util import SAFE_TALENT_COLUMNS, UNSAFE_TALENT_COLUMNS, select_fav, select_std
from scripts.models import Companies, Employees, Favourites, Students, Temps, Programs
from scripts.mail_ops import send_mail


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


@app.route('/email-verification/<token>')
def email_verify(token):
    try:
        email = confirm_token(token)

        if not email:
            return jsonify({'message': 'The confirmation link is invalid or has expired.'}), 400

        temp_student = Temps.query.filter_by(email=email).first()

        if Students.query.filter_by(email=email).first():
            return jsonify({'message': 'Email already verified'}), 400

        # Transfer from Temps to Students Table
        student = Students(temp_student.email, temp_student.password, temp_student.name, temp_student.surname)
        db.session.add(student)
        db.session.delete(temp_student) # Remove temp student from Temps
        db.session.commit()
        return jsonify({'message': 'Email verified successfully'}), 200
    except Exception as e:
        log_body = f'Student > Email Verification > ERROR > {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


# ========================================================================================
#   STUDENT Routes
# ========================================================================================
@app.route('/student/register', methods=['POST'])
def student_register():
    try:
        data = request.get_json()
        email = data['email']
        password = data['password']
        name = data['name']
        surname = data['surname']

        if Students.query.filter_by(email=email).first():
            return jsonify({'message': 'Student already registered'}), 400

        temp_student = Temps.query.filter_by(email=email).first()
        if not temp_student:
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

            db.session.add(student)
            db.session.commit()
        except Exception as e:
            log_body = f'Student > Register > Request Operation > ERROR > {repr(e)}'
            logging.warning(f'IP: {request.remote_addr} | {log_body}')
            return jsonify({'message': 'Something went wrong'}), 500

        return jsonify({'message': 'Student created successfully'}), 200
    except Exception as e:
        log_body = f'Student > Register > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/student/login', methods=['POST'])
def student_login():
    try:
        data = request.get_json()
        email = data['email']
        password = data['password']

        student = Students.query.filter_by(email=email).first()
        if not student:
            return jsonify({'message': 'Student does not exist'}), 400

        token_identity = {'user_type': 'student', 'email': email, 'profile_complete': student.profile_complete}

        if bcrypt.check_password_hash(student.password, password):
            access_token = create_access_token(identity=token_identity)
            return jsonify({'name': student.name, 'surname': student.surname, 'access_token': access_token}), 200
        else:
            return jsonify({'message': 'Incorrect password or email'}), 400
        
    except Exception as e:
        log_body = f'Student > Login > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


# ========================================================================================
#   Profile Update Section
# ========================================================================================
#   General, Activities, Hardskills, Softskills, Job, Settings
#   'Settings' route will be coded later -> features mail sending, changing email and password
@app.route('/student/profile-update/general', methods=['GET', 'POST'])
@jwt_required()
def profile_update_general():
    return update_profile_data(request, get_jwt_identity(), Students, DC_ST_GENERAL)


@app.route('/student/profile-update/activities', methods=['GET', 'POST'])
@jwt_required()
def profile_update_activities():
    return update_profile_data(request, get_jwt_identity(), Students, DC_ST_ACTIVITIES)


@app.route('/student/profile-update/hardskills', methods=['GET', 'POST'])
@jwt_required()
def profile_update_hardskills():
    return update_profile_data(request, get_jwt_identity(), Students, DC_ST_HARDSKILLS)


@app.route('/student/profile-update/job', methods=['GET', 'POST'])
@jwt_required()
def profile_update_job():
    return update_profile_data(request, get_jwt_identity(), Students, DC_ST_JOB)


@app.route('/student/profile-update/settings/change-password', methods=['POST'])
@jwt_required()
def profile_update_settings():
    try:
        jwt_data = get_jwt_identity()
        user_type = jwt_data['user_type']
        email = jwt_data['email']

        data = request.get_json()
        new_password = data['new_password']
        password = data['password']

        if user_type != 'student':
            return jsonify({'message': 'You are not a student'}), 400

        student = Students.query.filter_by(email=email).first()
        
        if not student:
            return jsonify({'message': 'Student does not exist'}), 400

        if not bcrypt.check_password_hash(student.password, password):
            return jsonify({'message': 'Incorrect password'}), 400
        
        token = generate_confirmation_token([email, new_password])

        if token == -1:
            return jsonify({'message': 'An error has occured while trying to send email'}), 400

        confirm_url = FRONTEND_LINK + '/student/confirm-new-password/' + token
        msg = 'Please click the link to confirm your new password: {} '.format(confirm_url)
        send_mail(student.email, 'Password Change', msg)

        return jsonify({'message': 'Verification email sent'}), 200
    except Exception as e:
        log_body = f'Student > Profile Update Settings > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong. ' + repr(e)}), 500


@app.route('/student/confirm-new-password/<token>')
def student_confirm_new_password(token):
    try:
        email, new_password = confirm_token(token)

        if not email:
            return jsonify({'message': 'The confirmation link is invalid or has expired.'}), 400

        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        student = Students.query.filter_by(email=email).first()

        if not Students.query.filter_by(email=email).first():
            return jsonify({'message': 'Student does not exist'}), 400

        setattr(student, 'password', hashed_password)
        db.session.commit()
        
        return jsonify({'message': 'Password changed successfully'}), 200
    except Exception as e:
        log_body = f'Student > Confirm New Password > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/student/forgot-password', methods=['POST'])
def student_forgot_password():
    try:
        data = request.get_json()
        email = data['email']

        student = Students.query.filter_by(email=email).first()

        if not student:
            return jsonify({'message': 'Student does not exist'}), 400
        
        token = generate_confirmation_token(email)

        if token == -1:
            return jsonify({'message': 'An error has occured while trying to send email.'}), 400

        confirm_url = FRONTEND_LINK + '/student/reset-password/' + token
        msg = 'Please click the link to reset your password: {} '.format(confirm_url)
        send_mail(student.email, 'Password Reset', msg)

        return jsonify({'message': 'Verification email sent'}), 200
    except Exception as e:
        log_body = f'Student > Forgot Password > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong. ' + repr(e)}), 500


@app.route('/student/reset-password/<token>', methods=['POST'])
def student_reset_password(token):
    try:
        data = request.get_json()
        new_password = data['new_password']

        email = confirm_token(token)

        if not email:
            return jsonify({'message': 'The confirmation link is invalid or has expired.'}), 400

        student = Students.query.filter_by(email=email).first()

        if not Students.query.filter_by(email=email).first():
            return jsonify({'message': 'Student does not exist'}), 400

        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        setattr(student, 'password', hashed_password)
        db.session.commit()
        
        return jsonify({'message': 'Password reset successfully'}), 200
    except Exception as e:
        log_body = f'Student > Reset Password > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong. ' + repr(e)}), 500


# ========================================================================================
#   End of STUDENT Routes
# ========================================================================================


# ========================================================================================
#   EMPLOYEE Routes
# ========================================================================================
@app.route('/employee/register', methods=['POST'])
def employee_register():
    try:
        data = request.get_json()
        email = data['email']
        password = data['password']
        name = data['name']
        surname = data['surname']
        special_id = data['special_id']

        company = Companies.query.filter_by(special_id=special_id).first()
        if not company:
            return jsonify({'message': 'Special ID does not exist'}), 400

        company_users = company.company_users
        if not email in company_users:
            return jsonify({'message': 'Email is not approved'}), 400

        if Employees.query.filter_by(email=email).first():
            return jsonify({'message': 'Email already exists'}), 400

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        employee = Employees(name, surname, email, hashed_password, company_id=company.id)

        db.session.add(employee)
        db.session.commit()

        return jsonify({'message': 'User created successfully'}), 200
    except Exception as e:
        log_body = f'Employee > Register > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500
    

@app.route('/employee/login', methods=['POST'])
def employee_login():
    try:
        data = request.get_json()
        email = data['email']
        password = data['password']

        employee = Employees.query.filter_by(email=email).first()

        if not employee:
            return jsonify({'message': 'Employee does not exist'}), 400

        token_identity = {'user_type': 'employee', 'email': email}

        if bcrypt.check_password_hash(employee.password, password):
            access_token = create_access_token(identity=token_identity)
            return jsonify({'access_token': access_token}), 200
        else:
            return jsonify({'message': 'Incorrect password or email'}), 400
    except Exception as e:
        log_body = f'Employee > Login > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500

@app.route('/employee/talent-market/<int:page_no>', methods=['GET'])
@jwt_required()
def employee_talent_get(page_no):
    try:
        jwt_identitiy = get_jwt_identity()
        user_type = jwt_identitiy['user_type']
        email = jwt_identitiy['email']

        if user_type != 'employee':
            return jsonify({'message': 'You are not an employee'}), 400
        
        employee = Employees.query.filter_by(email=email).first()

        if not employee:
            return jsonify({'message': 'Employee does not exist'}), 400

        data = request.get_json()
        
        entry_amount    = data['entry_amount']
        selected_sort   = data['selected_sort']
        selected_filter = data['selected_filter']
        is_ascending       = data['ascending']

        limit = entry_amount
        offset = (page_no - 1) * entry_amount

        students_list = db_filter_employee("students", selected_filter, selected_sort, is_ascending, limit, offset, selected_columns=SAFE_TALENT_COLUMNS)

        return jsonify({'students': students_list, "t_c": employee.t_c}), 200
    except Exception as e:
        log_body = f'Employee > Talent Market > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500

@app.route('/employee/add-favourite', methods=['POST'])
@jwt_required()
def employee_add_favourite():
    try:
        jwt_identitiy = get_jwt_identity()
        user_type = jwt_identitiy['user_type']
        email = jwt_identitiy['email']

        if user_type != 'employee':
            return jsonify({'message': 'You are not an employee'}), 400
        
        employee = Employees.query.filter_by(email=email).first()

        if not employee:
            return jsonify({'message': 'Employee does not exist'}), 400

        data = request.get_json()
        student_id = data['id']
        student = Students.query.filter_by(id=student_id).first()

        if not student:
            return jsonify({'message': 'Student does not exist'}), 400

        employee_id = employee.id
        company_id = employee.company_ref.id

        if Favourites.query.filter_by(student_id=student_id, employee_id=employee_id, company_id=company_id).first():
            return jsonify({'message': 'Student is already in favourites'}), 400

        favourite = Favourites(student_id, employee_id, company_id)
        db.session.add(favourite)
        db.session.commit()

        return jsonify({'message': 'Student added to favourites'}), 200

    except Exception as e:
        log_body = f'Employee > Add Favourite > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500

@app.route('/employee/remove-favourite', methods=['POST'])
@jwt_required()
def employee_remove_favourite():
    try:
        jwt_identitiy = get_jwt_identity()
        user_type = jwt_identitiy['user_type']
        email = jwt_identitiy['email']

        if user_type != 'employee':
            return jsonify({'message': 'You are not an employee'}), 400
        
        employee = Employees.query.filter_by(email=email).first()

        if not employee:
            return jsonify({'message': 'Employee does not exist'}), 400

        data = request.get_json()
        student_id = data['id']
        student = Students.query.filter_by(id=student_id).first()

        if not student:
            return jsonify({'message': 'Student does not exist'}), 400

        employee_id = employee.id
        company_id = employee.company_ref.id

        try:
            favourite = Favourites.query.filter_by(student_id=student_id, employee_id=employee_id, company_id=company_id).first()
            db.session.delete(favourite)
            db.session.commit()

            return jsonify({'message': 'Student removed from favourites'}), 200

        except Exception as e:
            log_body = f'Employee > Remove Favourite Database > ERROR : {repr(e)}'
            logging.warning(f'IP: {request.remote_addr} | {log_body}')
            return jsonify({'message': 'Something went wrong'}), 500

    except Exception as e:
        log_body = f'Employee > Remove Favourite > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500

@app.route('/employee/my-favourites', methods=['GET'])
@jwt_required()
def employee_my_favourites():

    jwt_identitiy = get_jwt_identity()
    user_type = jwt_identitiy['user_type']
    email = jwt_identitiy['email']

    if user_type != 'employee':
        return jsonify({'message': 'You are not an employee'}), 400
    
    employee = Employees.query.filter_by(email=email).first()

    if not employee:
        return jsonify({'message': 'Employee does not exist'}), 400

    my_favourites = Favourites.query.filter_by(employee_id=employee.id).all()
    students_list = list()
    
    for favourite in my_favourites:
        student = Students.query.filter_by(id=favourite.student_id).first()
        student_info = get_specific_data(student, select_fav(employee.t_c), get_raw=True, direct_data=True)
        students_list.append(student_info)

    return jsonify({'students': students_list, 't_c': employee.t_c}), 200

@app.route('/employee/student-profile/<int:student_id>', methods=['GET'])
@jwt_required()
def employee_student_profile(student_id):
    try:
        jwt_identitiy = get_jwt_identity()
        user_type = jwt_identitiy['user_type']
        email = jwt_identitiy['email']

        if user_type != 'employee':
            return jsonify({'message': 'You are not an employee'}), 400
        
        employee = Employees.query.filter_by(email=email).first()

        if not employee:
            return jsonify({'message': 'Employee does not exist'}), 400

        student = Students.query.filter_by(id=student_id).first()

        if not student:
            return jsonify({'message': 'Student does not exist'}), 400

        student_info = get_specific_data(student, select_std(employee.t_c), get_raw=True, direct_data=True)

        return jsonify({'student': student_info, 't_c': employee.t_c}), 200

    except Exception as e:
        log_body = f'Employee > Student Profile > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500

@app.route('/employee/t-c', methods=['GET'])
@jwt_required()
def employee_t_c():
    try:
        jwt_identitiy = get_jwt_identity()
        user_type = jwt_identitiy['user_type']
        email = jwt_identitiy['email']

        if user_type != 'employee':
            return jsonify({'message': 'You are not an employee'}), 400
        
        employee = Employees.query.filter_by(email=email).first()

        if not employee:
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

            return jsonify({'t_c': employee.t_c, 't_c_date': employee.t_c_date, 't_c_expire_date': employee.t_c_expire_date, 'remaining_t_c': remaining}), 200
        return jsonify({'t_c': employee.t_c}), 200

    except Exception as e:
        log_body = f'Employee > T&C > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500

@app.route('/employee/t-c', methods=['POST'])
@jwt_required()
def employee_t_c_update():
    try:
        jwt_identitiy = get_jwt_identity()
        user_type = jwt_identitiy['user_type']
        email = jwt_identitiy['email']

        if user_type != 'employee':
            return jsonify({'message': 'You are not an employee'}), 400
        
        employee = Employees.query.filter_by(email=email).first()

        if not employee:
            return jsonify({'message': 'Employee does not exist'}), 400

        if employee.t_c:
            return jsonify({'message': 'You have already accepted the T&C'}), 400

        setattr(employee, 't_c', True)
        setattr(employee, 't_c_date', datetime.now())
        setattr(employee, 't_c_expire_date', datetime.now() + timedelta(6*30))

        db.session.commit()

        return jsonify({'message': 'T&C updated'}), 200

    except Exception as e:
        log_body = f'Employee > T&C > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


# ========================================================================================
#   End of EMPLOYEE Routes
# ========================================================================================


# ========================================================================================
#   ADMINISTRATOR Routes
# ========================================================================================
@app.route('/admin/login', methods=['POST'])
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
            return jsonify({'message': 'Incorrect password or email'}), 400

        token_identity = {'user_type': 'admin', 'login_date': datetime.now().timestamp()}
        access_token = create_access_token(identity=token_identity)
        
        return jsonify({'access_token': access_token}), 200

    except Exception as e:
        log_body = f'Admin > Login > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


# Give the server all the companies in DB
@app.route('/admin/company', methods=['GET'])
@jwt_required()
def admin_test_companies():
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']
        if user_type != 'admin':
            return jsonify({'message': 'You are not an administrator'}), 400

        try:
            companies = Companies.query.all()
            companies = [get_specific_data(company, DC_AD_COMPANIES, get_raw=True) for company in companies]
            return jsonify({'companies': companies}), 200

        except Exception as e:
            log_body = f'Admin > Companies > Request Operation > ERROR : {repr(e)}'
            logging.warning(f'IP: {request.remote_addr} | {log_body}')
            return jsonify({'message': 'Something went wrong'}), 500

    except Exception as e:
        log_body = f'Admin > Companies > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


# Admin registers a new company into DB
@app.route('/admin/company/register', methods=['POST'])
@jwt_required()
def company_register():
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            return jsonify({'message': 'You are not an administrator'}), 400

        try:
            data = request.get_json()
            company_name = data['company_name'].lower()
            special_id = random_id_generator(8)
            company_users = data['company_users']

            # TODO: frontendde kontrol edilmiyorsa, duplicate emailleri silme operasyonu yapılsın

            if Companies.query.filter_by(company_name=company_name).first():
                return jsonify({'message': 'Company already exists'}), 400

            # Try for a few times to generate a special id
            for x in range(20):
                if Companies.query.filter_by(special_id=special_id).first():
                    special_id = random_id_generator(8)
                else:
                    break

            # If the special id is still taken, return an error
            if Companies.query.filter_by(special_id=special_id).first():
                    return jsonify({'message' : 'Couldn\'t generate a special ID. Please try again.'}), 500

            for em in company_users:
                if Employees.query.filter_by(email=em).first():
                    company_users.remove(em)

            company = Companies(company_name, special_id, company_users)
            db.session.add(company)
            db.session.commit()

            if company_users:
                # Send mails to employees so they know they can register
                for em in company_users:
                    register_url = FRONTEND_LINK + '/employee/register'
                    subj = 'Dear {} Employee'.format(company.company_name.upper())
                    msg = 'You can register at {} with this id: {}'.format(register_url, company.special_id)
                    send_mail(em, subj, msg)

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
@app.route('/admin/company/remove-company', methods=['POST'])
@jwt_required()
def company_remove():
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            return jsonify({'message': 'You are not an administrator'}), 400

        try:
            data = request.get_json()
            company_name = data['company_name'].lower()

            company = Companies.query.filter_by(company_name=company_name).first()

            if not company:
                return jsonify({'message': 'Company does not exist'}), 400

            db.session.delete(company)
            db.session.commit()
            return jsonify({'message': 'Company removed successfully'}), 201
        except Exception as e:
            log_body = f'Admin > Remove Company > Request Operation > ERROR : {repr(e)}'
            logging.warning(f'IP: {request.remote_addr} | {log_body}')
            return jsonify({'message': 'Something went wrong'}), 500

    except Exception as e:
        log_body = f'Admin > Remove Company > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


# Admin gets specific company's data
@app.route('/admin/company/<company_name>', methods=['GET'])
@jwt_required()
def get_company(company_name):
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            return jsonify({'message': 'You are not an administrator'}), 400

        try:
            company = Companies.query.filter_by(company_name=company_name).first()
            if not company:
                return jsonify({'message': 'Company does not exist'}), 400

            return jsonify(get_specific_data(company, DC_AD_COMPANIES, get_raw=True)), 200

        except Exception as e:
            log_body = f'Admin > Get Company > Request Operation > ERROR : {repr(e)}'
            logging.warning(f'IP: {request.remote_addr} | {log_body}')
            return jsonify({'message': 'Something went wrong'}), 500

    except Exception as e:
        log_body = f'Admin > Get Company > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


# Admin changes specific company's data (CANNOT ADD NEW EMPLOYEE MAILS HERE)
@app.route('/admin/company/<company_name>/edit', methods=['POST'])
@jwt_required()
def edit_company(company_name):
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            return jsonify({'message': 'You are not an administrator'}), 400

        try:
            company = Companies.query.filter_by(company_name=company_name).first()
            if not company:
                return jsonify({'message': 'Company does not exist'}), 400

            data = request.get_json()

            if "company_users" in data.keys():
                del data["company_users"]

            if "company_name" in data.keys():
                data["company_name"] = data["company_name"].lower()

            for key, value in data.items():
                try:
                    setattr(company, key, value)
                except Exception as e:
                    log_body = f'Admin > Company Edit > setattr > ERROR : {repr(e)}'
                    logging.warning(f'IP: {request.remote_addr} | {log_body}')
            
            db.session.commit()
            return jsonify({'message': 'Company updated successfully. '}), 200

        except Exception as e:
            log_body = f'Admin > Company Edit > Request Operation > ERROR : {repr(e)}'
            logging.warning(f'IP: {request.remote_addr} | {log_body}')
            return jsonify({'message': 'Something went wrong'}), 500

    except Exception as e:
        log_body = f'Admin > Company Edit > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


# Admin adds new employee mails to a company
# TODO: SEND EMAIL TO EMPLOYEES ADDED HERE!!!!!!
@app.route('/admin/company/<company_name>/add-employee', methods=['POST'])
@jwt_required()
def company_add_user(company_name):
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            return jsonify({'message': 'You are not an administrator'}), 400

        data = request.get_json()
        new_employees = data['company_users']
        
        try:
            company = Companies.query.filter_by(company_name=company_name).first()
            if not company:
                return jsonify({'message': 'Company does not exist'}), 400

            current_employees = company.company_users
            if not current_employees:
                setattr(company, 'company_users', new_employees)
                db.session.commit()
                return jsonify({'message': 'Employees updated succesfully. Added: ' + str(new_employees)}), 200

            employees_to_add = []
            for em in new_employees:
                if Employees.query.filter_by(email=em).first():
                    continue

                if em not in current_employees:
                    employees_to_add.append(em)
            
            if not employees_to_add:
                return jsonify({'message': 'No new employees to add'}), 400

            final_employees = company.company_users + employees_to_add
            
            setattr(company, 'company_users', final_employees)
            db.session.commit()

            # Send mails to employees so they know they can register
            for em in employees_to_add:
                register_url = FRONTEND_LINK + '/employee/register'
                subj = 'Dear {} Employee'.format(company.company_name.upper())
                msg = f'You can register at {register_url} with this id: {company.special_id}'
                send_mail(em, subj, msg)

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
@app.route('/admin/company/<company_name>/remove-employee', methods=['POST'])
@jwt_required()
def company_remove_user(company_name):
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            return jsonify({'message': 'You are not an administrator'}), 400

        data = request.get_json()
        employee_to_remove = data['employee_mail']
        
        try:
            company = Companies.query.filter_by(company_name=company_name).first()
            current_employees = company.company_users[:]

            if not current_employees:
                return jsonify({'message': 'Company does not have any employees'}), 400

            if employee_to_remove in current_employees:
                current_employees.remove(employee_to_remove)
                
            setattr(company, 'company_users', current_employees)
            db.session.commit()
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
@jwt_required()
def admin_employees(page_no):
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            return jsonify({'message': 'You are not an administrator'}), 400

        if page_no < 1:
            return jsonify({'message': 'Page number must at least be 1'}), 400

        data = request.get_json()
        
        entry_amount    = data['entry_amount']
        selected_sort   = data['selected_sort']
        selected_filter = data['selected_filter']
        is_ascending       = data['ascending']

        page_start =  (page_no - 1)*entry_amount + 1
        page_end   = page_start + entry_amount
        
        # employee_sort = dict()
        # employee_sort['id']           = Employees.id
        # employee_sort['name']         = Employees.name
        # employee_sort['company_name'] = Employees.company_name
        # employee_sort['t_c']          = Employees.t_c
        # employee_sort['sign_up_date'] = Employees.sign_up_date

        employees = db_filter_admin('employees', selected_filter, selected_sort, is_ascending, page_start, page_end)

        # try:
        #     if ascending:
        #         if selected_filter == {}:
        #             employees = Employees.query.order_by(employee_sort[selected_sort].asc()).slice(page_start - 1, page_end - 1).all()
        #         else:
        #             employees = Employees.query.filter_by(**selected_filter).order_by(employee_sort[selected_sort].asc()).slice(page_start - 1, page_end - 1).all()
        #     else:
        #         if selected_filter == {}:
        #             employees = Employees.query.order_by(employee_sort[selected_sort].desc()).slice(page_start - 1, page_end - 1).all()
        #         else:
        #             employees = Employees.query.filter_by(**selected_filter).order_by(employee_sort[selected_sort].desc()).slice(page_start - 1, page_end - 1).all()
        # except Exception as e:
        #     log_body = f'Admin > Employees > Request Operation > ERROR : {repr(e)}'
        #     logging.warning(f'IP: {request.remote_addr} | {log_body}')
        #     return jsonify({'message': 'Selected sortable or filter does not exist'}), 400

        # employees = [get_specific_data(employee, DC_AD_EMPLOYEES, get_raw=True) for employee in employees]

        page_amount = ceil(len(employees) / entry_amount)

        return jsonify({'max_pages': page_amount, 'employees': employees}), 200
    except Exception as e:
        log_body = f'Admin > Employees > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500

@app.route('/admin/employee/get/<email>', methods=['GET'])
@jwt_required()
def admin_employee_get(email):
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            return jsonify({'message': 'You are not an administrator'}), 400

        employee = Employees.query.filter_by(email=email).first()

        if not employee:
            return jsonify({'message': 'Employee does not exist'}), 400

        employee = employee.to_dict()

        remove_info = ['pool_amount', 'sign_up_date', 'id']

        for info in remove_info:
            if info in employee.keys():
                del employee[info]

        return jsonify({**employee}), 200
    except Exception as e:
        log_body = f'Admin > Employee Get > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/admin/employee/edit/<email>', methods=['POST'])
@jwt_required()
def admin_employee_edit(email):
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            return jsonify({'message': 'You are not an administrator'}), 400

        data = request.get_json()['values']

        if 'password' in data.keys():
            del data['password']
        
        if 'company' in data.keys():
            del data['company']
        
        if 'company_name' in data.keys():
            del data['company_name']

        try:
            employee = Employees.query.filter_by(email=email).first()
            if not employee:
                return jsonify({'message': 'Employee does not exist'}), 400

            for key, value in data.items():
                setattr(employee, key, value)
            db.session.commit()
            
        except Exception as e:
            log_body = f'Admin > Employee Edit > Request Operation > ERROR : {repr(e)}'
            logging.warning(f'IP: {request.remote_addr} | {log_body}')
            return jsonify({'message': 'Something went wrong in request operations'}), 500

        return jsonify({'message': 'Employee edited succesfully'}), 200
    except Exception as e:
        log_body = f'Admin > Employee Edit > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/admin/employee/multiple-remove', methods=['POST'])
@jwt_required()
def admin_employees_multiple_remove():
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            return jsonify({'message': 'You are not an administrator'}), 400

        data = request.get_json()
        employees_to_remove = data['removed_users']
        
        employees_removed = []

        try:
            for employee in employees_to_remove:
                try:
                    employee = Employees.query.filter_by(email=employee).first()
                    if employee:
                        employees_removed.append(employee.email)
                    db.session.delete(employee)
                    db.session.commit()
                except:
                    continue
            
            return jsonify({'message': 'Employees removed succesfully. Removed employees: ' + str(employees_removed)}), 200
        except Exception as e:
            log_body = f'Admin > Employees > Multiple Remove > Request Operation > ERROR : {repr(e)}'
            logging.warning(f'IP: {request.remote_addr} | {log_body}')
            return jsonify({'message': 'Something went wrong in request operations'}), 500

    except Exception as e:
        log_body = f'Admin > Employees > Multiple Remove > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


# Admin gets all the students' data (TODO: Only give the students in batches of 20 for example, aka paging)
@app.route('/admin/student/<int:page_no>', methods=['GET'])
@jwt_required()
def admin_students(page_no):
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            return jsonify({'message': 'You are not an administrator'}), 400

        if page_no < 1:
            return jsonify({'message': 'Page number must at least be 1'}), 400

        data = request.get_json()
        
        entry_amount    = data['entry_amount']
        selected_filter = data['selected_filter']
        selected_sort   = data['selected_sort']
        is_ascending       = data['ascending']

        page_start =  (page_no - 1)*entry_amount + 1
        page_end   = page_start + entry_amount
        
        # student_sort = dict()
        # student_sort['id']               = Students.id
        # student_sort['name']             = Students.name
        # # TODO: Bu olcak ama school_programs JSON'dan çekme falan -> student_sort['program_name']     = Students.program_name
        # student_sort['grad_status']      = Students.grad_status
        # student_sort['profile_complete'] = Students.profile_complete

        students = db_filter_admin('students', selected_filter, selected_sort, is_ascending, page_start, page_end)
        # try:
        #     if ascending:
        #         if selected_filter == {}:
        #             students = Students.query.order_by(student_sort[selected_sort].asc()).slice(page_start - 1, page_end - 1).all()
        #         else:
        #             students = Students.query.filter_by(**selected_filter).order_by(student_sort[selected_sort].asc()).slice(page_start - 1, page_end - 1).all()
        #     else:
        #         if selected_filter == {}:
        #             students = Students.query.order_by(student_sort[selected_sort].desc()).slice(page_start - 1, page_end - 1).all()
        #         else:
        #             students = Students.query.filter_by(**selected_filter).order_by(student_sort[selected_sort].desc()).slice(page_start - 1, page_end - 1).all()
        # except Exception as e:
        #     log_body = f'Admin > Students > Request Operation > ERROR : {repr(e)}'
        #     logging.warning(f'IP: {request.remote_addr} | {log_body}')
        #     return jsonify({'message': 'Selected sortable or filter does not exist'}), 400

        # students = [get_specific_data(student, DC_AD_STUDENT, get_raw=True) for student in students]

        page_amount = ceil(len(students) / entry_amount)
        
        return jsonify({'max_pages': page_amount, 'students': students}), 200
    except Exception as e:
        log_body = f'Admin > Students > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/admin/student/get/<email>', methods=['GET'])
@jwt_required()
def admin_student_get(email):
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            return jsonify({'message': 'You are not an administrator'}), 400

        student = Students.query.filter_by(email=email).first()

        if not student:
            return jsonify({'message': 'Student does not exist'}), 400

        student = student.to_dict()

        return jsonify({**student}), 200
    except Exception as e:
        log_body = f'Admin > Student Get > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/admin/student/edit/<email>', methods=['POST'])
@jwt_required()
def admin_student_edit(email):
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            return jsonify({'message': 'You are not an administrator'}), 400

        data = request.get_json()

        if 'job_find_time' in data:
            del data['job_find_time']

        if 'password' in data.keys():
            del data['password']

        try:
            student = Students.query.filter_by(email=email).first()
            if not student:
                return jsonify({'message': 'Student does not exist'}), 400

            for key, value in data.items():
                setattr(student, key, value)
            db.session.commit()
        except Exception as e:
            log_body = f'Admin > Student Edit > Request Operation > ERROR : {repr(e)}'
            logging.warning(f'IP: {request.remote_addr} | {log_body}')
            return jsonify({'message': 'Something went wrong in request operations'}), 500

        return jsonify({'message': 'Student edited succesfully'}), 200
    except Exception as e:
        log_body = f'Admin > Student Edit > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


# Admin - Multiple remove students
@app.route('/admin/student/multiple-remove', methods=['POST'])
@jwt_required()
def admin_students_multiple_remove():
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            return jsonify({'message': 'You are not an administrator'}), 400

        data = request.get_json()
        students_to_remove = data['removed_users']
        
        students_removed = []

        try:
            for student in students_to_remove:
                try:
                    student = Students.query.filter_by(email=student).first()
                    if student:
                        students_removed.append(student.email)
                    db.session.delete(student)
                    db.session.commit()
                except:
                    continue
            return jsonify({'message': 'Students removed succesfully. Removed students: ' + str(students_removed)}), 200
        except Exception as e:
            log_body = f'Admin > Students > Multiple Remove > Request Operation > ERROR : {repr(e)}'
            logging.warning(f'IP: {request.remote_addr} | {log_body}')
            return jsonify({'message': 'Something went wrong in request operations'}), 500

    except Exception as e:
        log_body = f'Admin > Students > Multiple Remove > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/admin/program/create', methods=['POST'])
@jwt_required()
def admin_create_program():
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            return jsonify({'message': 'You are not an administrator'}), 400

        data = request.get_json()
        program_name = data['program_name']
        program_code = data['program_code']

        if Programs.query.filter_by(program_code=program_code).filter_by(program_name=program_name).first():
            return jsonify({'message': 'Program already exists'}), 400

        program = Programs(program_name, program_code)
        db.session.add(program)
        db.session.commit()

        return jsonify({'message': 'Program created succesfully'}), 200

    except Exception as e:
        log_body = f'Admin > Programs > Create > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/admin/program/edit/<id>', methods=['POST'])
@jwt_required()
def admin_program_edit(id):
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            return jsonify({'message': 'You are not an administrator'}), 400

        data = request.get_json()

        new_program_name = data['program_name']
        new_program_code = data['program_code']

        program = Programs.query.filter_by(id=id).first()
        if not program:
            return jsonify({'message': 'Program does not exist'}), 400

        if program.program_code == new_program_code and program.program_name == new_program_name:
            return jsonify({'message': 'Same values given.'}), 400

        if Programs.query.filter_by(program_code=new_program_code).filter_by(program_name=new_program_name).first():
            return jsonify({'message': 'Program already exists'}), 400

        setattr(program, 'program_name', new_program_name)
        setattr(program, 'program_code', new_program_code)
        db.session.commit()

        return jsonify({'message': 'Program edited succesfully'}), 200
    except Exception as e:
        log_body = f'Admin > Program Edit > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/admin/program/invite', methods=['POST'])
@jwt_required()
def admin_program_invite_students():
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            return jsonify({'message': 'You are not an administrator'}), 400

        data = request.get_json()
        program_name = data['inviteProgramName']
        program_code = data['inviteProgramCode']
        students_to_invite = data['emails']

        if not students_to_invite:
            return jsonify({'message': 'No emails received'}), 400

        students_invited = []

        try:
            program = Programs.query.filter_by(program_name=program_name).filter_by(program_code=program_code).first()
            if not program:
                return jsonify({'message': 'Program does not exist'}), 400

            register_url = FRONTEND_LINK + '/student/register'

            for st_mail in students_to_invite:
                student = Students.query.filter_by(email=st_mail).first()
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
                            print(student.school_programs)
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
                    send_mail(st_mail, subj, msg)

                except Exception as e:
                    print('Error:', e)
            
            db.session.commit()
            
        except Exception as e:
            log_body = f'Admin > Program > Add Students > Request Operation > ERROR : {repr(e)}'
            logging.warning(f'IP: {request.remote_addr} | {log_body}')
            return jsonify({'message': 'Something went wrong in request operations'}), 500
        
        print('Invited emails: ' + str(students_invited))
        return jsonify({'message': 'Students invited succesfully: ' + str(students_invited)}), 200
    except Exception as e:
        log_body = f'Admin > Program > Add Students > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


# get programs
@app.route('/admin/program', methods=['GET'])
@jwt_required()
def admin_get_programs():
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            return jsonify({'message': 'You are not an administrator'}), 400

        programs = Programs.query.all()
        programs_list = []
        for program in programs:
            programs_list.append(program.to_dict())
        
        return jsonify({'programs': programs_list}), 200
    except Exception as e:
        log_body = f'Admin > Program > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500

@app.route('/admin/program/remove', methods=['POST'])
@jwt_required()
def admin_program_remove():
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            return jsonify({'message': 'You are not an administrator'}), 400

        data = request.get_json()
        program_name = data['program_name']
        program_code = data['program_code']

        try:
            program = Programs.query.filter_by(program_name=program_name).filter_by(program_code=program_code).first()
            if not program:
                return jsonify({'message': 'Program does not exist'}), 400

            db.session.delete(program)
            db.session.commit()
        except Exception as e:
            log_body = f'Admin > Program > Remove > Request Operation > ERROR : {repr(e)}'
            logging.warning(f'IP: {request.remote_addr} | {log_body}')
            return jsonify({'message': 'Something went wrong in request operations'}), 500

        return jsonify({'message': 'Program removed succesfully'}), 200
    except Exception as e:
        log_body = f'Admin > Program > Remove > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/admin/data', methods=['GET'])
@jwt_required()
def admin_data():
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            return jsonify({'message': 'You are not an administrator'}), 400

        all_students  = Students.query.all()
        all_temps     = Temps.query.all()
        all_programs  = Programs.query.all()
        all_companies = Companies.query.all()
        all_employees = Employees.query.all()

        students_table_count  = len(all_students)
        temps_table_count     = len(all_temps)
        programs_table_count  = len(all_programs)
        companies_table_count = len(all_companies)
        employees_table_count = len(all_employees)

        # Ortalama İş Bulma Süresi Grafiği
        if students_table_count != 0:
            avg_job_find_time = sum([student.job_find_time for student in all_students if student.job_find_time ]) / students_table_count
        else:
            avg_job_find_time = 0

        # Geçici
        avg_job_find_time = 158.91

        # Öğrenci Veri Grafiği
        student_grad_total      = students_table_count + temps_table_count
        student_signup_total    = students_table_count
        student_completed_total = Students.query.filter_by(profile_complete=True).count()

        # Employee Veri Grafiği
        employee_invite_total   = sum([len(company.company_users) for company in all_companies])
        employee_signup_total   = 1
        employee_tc_total       = 1

        grad_profile = {
            'grad_total': student_grad_total,
            'signup_total': student_signup_total,
            'completed_total' : student_completed_total
        }

        company_signup = {
            'grad_total': student_grad_total,
            'signup_total': student_signup_total,
            'completed_total' : student_completed_total
        }

        account_signup = {
            'invite_total' : employee_invite_total,
            'signup_total' : employee_signup_total,
            'total_tc' : employee_tc_total
        }

        employment_rate = {
            'employed' : 253,
            'self_employed' : 51,
            'unemployed' : 215
        }

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

        # This is going to be more complex than the others...
        # God have mercy.
        filter_top5 = {
            'location' : {
                'Remote' : 1,
                'Istanbul' : 2,
                'Bursa' : 3,
                'Ankara' : 4,
                'Van' : 5
            },
            'inner_peace' : {
                'remote' : 6,
                'Istanbul' : 7,
                'Bursa' : 8,
                'Ankara' : 9,
                'Van' : 10
            },
            'wrath' : {
                'remote' : 11,
                'Istanbul' : 12,
                'Bursa' : 13,
                'Ankara' : 14,
                'Van' : 15
            },
            'solitude' : {
                'remote' : 16,
                'Istanbul' : 17,
                'Bursa' : 18,
                'Ankara' : 19,
                'Van' : 20
            },
            'honesty' : {
                'remote' : 21,
                'Istanbul' : 22,
                'Bursa' : 23,
                'Ankara' : 24,
                'Van' : 25
            }
        }

        data = {
            'grad_profile': grad_profile,
            'company_signup': company_signup,
            'account_signup': account_signup,
            'employment_rate' : employment_rate,
            'grad_profile_programs' : grad_profile_programs,
            'avg_job_find_time' : avg_job_find_time,
            'filter_top5' : filter_top5
        }

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