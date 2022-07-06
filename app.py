from flask import request, jsonify, url_for
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity
from datetime import datetime, timedelta

import random
import json

from itsdangerous import URLSafeTimedSerializer

from sqlalchemy import delete
from scripts.util import app, bcrypt, jwt, db, get_specific_data, update_table_data, update_profile_data, random_id_generator
from scripts.util import DC_AD_STUDENT, DC_AD_COMPANIES, DC_AD_EMPLOYEES, DC_ST_GENERAL, DC_ST_ACTIVITIES, DC_ST_HARDSKILLS, DC_ST_SOFTSKILLS, DC_ST_JOB
from scripts.models import Companies, Employees, Favourites, Students, Temps, Programs, Pools
from scripts.mail_ops import send_mail


def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])


def confirm_token(token, expiration=18000):
    # 18000 is 5 hours.
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email


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
        print(e)
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
            return jsonify({'message': 'Email already exists'}), 400

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        temp_student = Temps(email, hashed_password, name, surname)
        db.session.add(temp_student)
        db.session.commit()

        token = generate_confirmation_token(temp_student.email)
        confirm_url = url_for('email_verify', token=token, _external=True)
        msg = 'Please click the link to activate your account: {} '.format(confirm_url)

        send_mail(temp_student.email, 'Verify Your Account', msg)

        return jsonify({'message': 'Student created successfully'}), 200
    except Exception as e:
        print(e)
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/student/login', methods=['POST'])
def student_login():
    try:
        data = request.get_json()
        email = data['email']
        password = data['password']

        student = Students.query.filter_by(email=email).first()
        temp_student = Temps.query.filter_by(email=email).first()

        # Student doesn't exist in DB
        if not student and not temp_student:
            return jsonify({'message': 'Student does not exist'}), 400

        # Student didn't verify their account -> Send another verification email
        if not student and temp_student:
            if bcrypt.check_password_hash(temp_student.password, password):
                # resend email verification
                token = generate_confirmation_token(temp_student.email)
                confirm_url = url_for('email_verify', token=token, _external=True)
                msg = 'Please click the link to activate your account {} '.format(confirm_url)
                send_mail(temp_student.email, 'Verify Your Account', msg)
                return jsonify({'message': 'Verification email sent'}), 401
            else:
                return jsonify({'message': 'Incorrect password or email'}), 400
        
        # Student exists in DB
        if student.profile_complete:
            token_identity = {'user_type': 'student', 'email': email}
        else:
            token_identity = {'user_type': 'student_incomplete', 'email': email}

        if bcrypt.check_password_hash(student.password, password):
            access_token = create_access_token(identity=token_identity)
            return jsonify({'Student Profile Complete': student.profile_complete, 'access_token': access_token}), 200
        else:
            return jsonify({'message': 'Incorrect password or email'}), 400
        
    except Exception as e:
        print(e)
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


@app.route('/student/profile-update/softskills', methods=['GET', 'POST'])
@jwt_required()
def profile_update_softskills():
    return update_profile_data(request, get_jwt_identity(), Students, DC_ST_SOFTSKILLS)


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

        if user_type != 'student' and user_type != 'student_incomplete':
            return jsonify({'message': 'You are not a student'}), 400

        student = Students.query.filter_by(email=email).first()
        
        if not student:
            return jsonify({'message': 'Student does not exist'}), 400

        if not bcrypt.check_password_hash(student.password, password):
            return jsonify({'message': 'Incorrect password'}), 400
        
        token = generate_confirmation_token([email, new_password])
        #confirm_url = url_for('student_confirm_new_password', token=token, _external=True)
        confirm_url = 'http://localhost:3000' + '/student/confirm-new-password/<token>'
        msg = 'Please click the link to confirm your new password: {} '.format(confirm_url)
        send_mail(student.email, 'Password Change', msg)

        return jsonify({'message': 'Verification email sent'}), 200
    except Exception as e:
        print(e)
        return jsonify({'message': 'Something went wrong. ' + str(e)}), 500


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
        print(e)
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
        confirm_url = url_for('student_reset_password', token=token, _external=True)
        msg = 'Please click the link to reset your password: {} '.format(confirm_url)
        send_mail(student.email, 'Password Reset', msg)

        return jsonify({'message': 'Verification email sent'}), 200
    except Exception as e:
        print(e)
        return jsonify({'message': 'Something went wrong. ' + str(e)}), 500


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
        print(e)
        return jsonify({'message': 'Something went wrong. ' + str(e)}), 500


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
        employee = Employees(name, surname, email, hashed_password, special_id)

        setattr(employee, "t_c", False)
        setattr(employee, "duration", 0)
        setattr(employee, "pool_amount", 0)
        setattr(employee, "fav_amount", 0)
        db.session.add(employee)
        db.session.commit()

        return jsonify({'message': 'User created successfully'}), 200
    except Exception as e:
        print(e)
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
    except:
        return jsonify({'message': 'Something went wrong'}), 500

# DENEME
@app.route('/employee/talent-market', methods=['GET'])
@jwt_required()
def employee_talent_get():
    try:
        data = get_jwt_identity()
        user_type = data['user_type']
        email = data['email']

        if user_type != 'employee':
            return jsonify({'message': 'You are not an employee'}), 400
        
        employee = Employees.query.filter_by(email=email).first()

        if not employee:
            return jsonify({'message': 'Employee does not exist'}), 400

        students = Students.query.all()
        students_list = [student.to_dict() for student in students if student.profile_complete]

        print('Sent students:', students_list)

        return jsonify({'students': students_list}), 200
    except Exception as e:
        print(e)
        return jsonify({'message': 'Something went wrong'}), 500

# DENEME
@app.route('/employee/talent-market/<student_email>', methods=['POST'])
@jwt_required()
def employee_talent_add(student_email):
    try:
        data = get_jwt_identity()
        user_type = data['user_type']
        email = data['email']

        if user_type != 'employee':
            return jsonify({'message': 'You are not an employee'}), 400
        
        employee = Employees.query.filter_by(email=email).first()

        if not employee:
            return jsonify({'message': 'Employee does not exist'}), 400

        data = request.get_json()
        
        student = Students.query.filter_by(email=student_email).first()

        if not student:
            return jsonify({'message': 'Student does not exist'}), 400

        if not student.profile_complete:
            return jsonify({'message': 'Student has an incomplete profile'}), 400

        company_name = Companies.query.filter_by(special_id=employee.company).first().company_name
        talent = Favourites(student.id, company_name, employee.email)
        db.session.add(talent)
        db.session.commit()

        return jsonify({'message': 'Student profile updated'}), 200
    except Exception as e:
        print(e)
        return jsonify({'message': 'Something went wrong'}), 500

# DENEME
@app.route('/employee/company-pool', methods=['GET'])
@jwt_required()
def employee_company_pool_get():
    try:
        data = get_jwt_identity()
        user_type = data['user_type']
        email = data['email']

        if user_type != 'employee':
            return jsonify({'message': 'You are not an employee'}), 400
        
        employee = Employees.query.filter_by(email=email).first()

        if not employee:
            return jsonify({'message': 'Employee does not exist'}), 400

        company_name = Companies.query.filter_by(special_id=employee.company).first().company_name

        talents = [talent for talent in Favourites.query.filter_by(company_name=company_name).all()]

        print('Sent talents:', talents)

        return jsonify({'talents': talents}), 200
    except Exception as e:
        print(e)
        return jsonify({'message': 'Something went wrong'}), 500


# These are for later
# /employee/featured_talents
# /employee/featured_talents/<email>


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
        except:
            return jsonify({'message': 'Something went wrong'}), 500

        admin = dict(admin)

        if email != admin['email'] or admin['password'] != password:
            return jsonify({'message': 'Incorrect password or email'}), 400

        token_identity = {'user_type': 'admin', 'login_date': datetime.now().timestamp()}
        access_token = create_access_token(identity=token_identity)
        
        return jsonify({'access_token': access_token}), 200

    except Exception as e:
        print(e)
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
            print(e)
            return jsonify({'message': 'Something went wrong'}), 500

    except Exception as e:
        print(e)
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
            company_name = data['company_name']
            #special_id = data['special_id']
            special_id = random_id_generator(4)
            company_users = data['company_users']

            # TODO: frontendde yoksa kontrol, duplicate emailleri silme operasyonu yapılsın

            if Companies.query.filter_by(company_name=company_name).first():
                return jsonify({'message': 'Company already exists'}), 400

            if Companies.query.filter_by(special_id=special_id):
                special_id = random_id_generator(4)

            company = Companies(company_name, special_id, company_users)
            db.session.add(company)
            db.session.commit()

            # Send mails to employees so they know they can register
            for em in company_users:
                register_url = url_for('employee_register', _external=True)
                subj = 'Dear {} Employee'.format(company.company_name)
                msg = 'You can register at {} with this id: {}'.format(register_url, special_id)
                send_mail(em, subj, msg)

            return jsonify({'message': 'Company created successfully'}), 201
        except Exception as e:
            print(e)
            return jsonify({'message': 'Something went wrong'}), 500

    except Exception as e:
        print(e)
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
            company_name = data['company_name']

            company = Companies.query.filter_by(company_name=company_name).first()

            if not company:
                return jsonify({'message': 'Company does not exist'}), 400

            db.session.delete(company)
            db.session.commit()
            return jsonify({'message': 'Company removed successfully'}), 201
        except Exception as e:
            print(e)
            return jsonify({'message': 'Something went wrong'}), 500

    except Exception as e:
        print(e)
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
            print(e)
            return jsonify({'message': 'Something went wrong'}), 500

    except Exception as e:
        print(e)
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

            for key, value in data.items():
                try:
                    setattr(company, key, value)
                except Exception as e:
                    print(e)
                    
            return jsonify({'message': 'User updated successfully. '}), 200

        except Exception as e:
            print(e)
            return jsonify({'message': 'Something went wrong'}), 500

    except Exception as e:
        print(e)
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
            current_employees = company.company_users

            if not current_employees:
                setattr(company, 'company_users', new_employees)
                db.session.commit()
                return jsonify({'message': 'Employees updated succesfully. Current: ' + str(new_employees)}), 200

            employees_to_add = []
            for em in new_employees:
                if em not in current_employees:
                    employees_to_add.append(em)
            
            if not employees_to_add:
                return jsonify({'message': 'No new employees to add'}), 400

            final_employees = company.company_users + employees_to_add
            
            setattr(company, 'company_users', final_employees)
            db.session.commit()
            return jsonify({'message': 'Employees updated succesfully. Current: ' + str(final_employees)}), 200
        except Exception as e:
            print(e)
            return jsonify({'message': 'Something went wrong in request operations'}), 500

    except Exception as e:
        print(e)
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
            print(e)
            return jsonify({'message': 'Something went wrong in request operations'}), 500

    except Exception as e:
        print(e)
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/admin/employee/page-<int:page_no>', methods=['GET'])
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
        entry_amount = data['entry_amount']
        selected_filter = data['selected_filter']

        

        page_start =  (page_no - 1)*entry_amount + 1
        page_end   = page_start + entry_amount

        employees = None
        if selected_filter == 'id':
            employees = Employees.query.order_by(Employees.id.asc()).slice(page_start - 1, page_end - 1).all()
        elif selected_filter == 'name':
            employees = Employees.query.order_by(Employees.name.asc()).slice(page_start - 1, page_end - 1).all()
        elif selected_filter == 'company_name':
            employees = Employees.query.order_by(Employees.company_name.asc()).slice(page_start - 1, page_end - 1).all()
        elif selected_filter == 't_c':
            employees = Employees.query.order_by(Employees.t_c.asc()).slice(page_start - 1, page_end - 1).all()
        else:
            return jsonify({'message': 'Selected filter does not exist'}), 400

        employees = [get_specific_data(employee, DC_AD_EMPLOYEES, get_raw=True) for employee in employees]
        return jsonify({'employees': employees}), 200

    except Exception as e:
        print(e)
        return jsonify({'message': 'Something went wrong'}), 500


# Admin gets all the students' data (TODO: Only give the students in batches of 20 for example, aka paging)
@app.route('/admin/student/page-<int:page_no>', methods=['GET'])
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
        entry_amount = data['entry_amount']
        selected_filter = data['selected_filter']

        

        page_start =  (page_no - 1)*entry_amount + 1
        page_end   = page_start + entry_amount
        
        students = None
        if selected_filter == 'id':
            students = Students.query.order_by(Students.id.asc()).slice(page_start - 1, page_end - 1).all()
        elif selected_filter == 'name':
            students = Students.query.order_by(Students.name.asc()).slice(page_start - 1, page_end - 1).all()
        elif selected_filter == 'program_name':
            students = Students.query.order_by(Students.program_name.asc()).slice(page_start - 1, page_end - 1).all()
        elif selected_filter == 'grad_status':
            students = Students.query.order_by(Students.grad_status.asc()).slice(page_start - 1, page_end - 1).all()
        elif selected_filter == 'profile_complete':
            students = Students.query.order_by(Students.profile_complete.asc()).slice(page_start - 1, page_end - 1).all()
        else:
            return jsonify({'message': 'Selected filter does not exist'}), 400

        students = [get_specific_data(student, DC_AD_STUDENT, get_raw=True) for student in students]
        return jsonify({'students': students}), 200
    except Exception as e:
        print(e)
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/admin/create-program', methods=['POST'])
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
        emails       = data['emails']

        if Programs.query.filter_by(program_name).first():
            return jsonify({'message': 'Program already exists'}), 400

        if Programs.query.filter_by(program_code).first():
            return jsonify({'message': 'Program code is already in use'}), 400

        # TODO: EMAIL YOLLAMA KISIMLARI
        #       ya burada, ya da session.commit() ten sonra mail yollama

        """
        for mail in emails:
            if Students.query.filter_by(email=mail).first():
                print(f'Following email is already in Students table: {mail}')
                continue
            if Temps.query.filter_by(email=mail).first():
                print(f'Following email is already in Temps table: {mail}')
                continue
            
            try:
                # Add Student to Temps table????????????????????????**
                # Send the mail now
                register_url = url_for('student_register', _external=True)
                subj = 'Dear {} Graduate'.format(program_name)
                msg = 'You can register at {} with this code: {}'.format(register_url, program_code)
                send_mail(mail, subj, msg)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print('Error:', e)

        """

        program = Programs(program_name, program_code)
        db.session.add(program)
        db.session.commit()
        
        return jsonify({'message': 'Program created succesfully'}), 200

    except Exception as e:
        print(e)
        return jsonify({'message': 'Something went wrong'}), 500


# ========================================================================================
#   End of ADMINISTRATOR Routes
# ========================================================================================


if __name__ == '__main__':
    app.run(debug=True)