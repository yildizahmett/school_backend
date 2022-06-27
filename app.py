from flask import request, jsonify, url_for
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity
from datetime import datetime, timedelta
import os
import random
import json

from itsdangerous import URLSafeTimedSerializer

from sqlalchemy import delete
from scripts.util import app, bcrypt, jwt, db, get_specific_data, update_table_data, update_profile_data
from scripts.models import Companies, Employees, Favourites, Students, Temps
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
                return jsonify({'message': 'Verification email sent'}), 200
            else:
                return jsonify({'message': 'Incorrect password or email'}), 400
        
        # Student exists in DB
        if student.profile_complete == True:
            token_identity = {'user_type': 'student_incomplete', 'email': email}
        else:
            token_identity = {'user_type': 'student', 'email': email}

        if bcrypt.check_password_hash(student.password, password):
            access_token = create_access_token(identity=token_identity)
            return jsonify({'Student Profile Complete': student.profile_complete, 'access_token': access_token}), 200
        else:
            return jsonify({'message': 'Incorrect password or email'}), 400
        
    except Exception as e:
        print(e)
        return jsonify({'message': 'Something went wrong'}), 500
    

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
        user = Employees(name, surname, email, hashed_password, special_id)
        db.session.add(user)
        db.session.commit()

        return jsonify({'message': 'User created successfully'}), 200
    except:
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

# ========================================================================================
#   Profile Update Section
# ========================================================================================
#   General, Activities, Hardskills, Softskills, Job, Settings
#   'Settings' route will be coded later -> features mail sending, changing email and password

@app.route('/student/profile-update/general', methods=['GET', 'POST'])
@jwt_required()
def profile_update_general():
    return update_profile_data(request, get_jwt_identity(), Students, 'general')


@app.route('/student/profile-update/activities', methods=['GET', 'POST'])
@jwt_required()
def profile_update_activities():
    return update_profile_data(request, get_jwt_identity(), Students, 'activities')


@app.route('/student/profile-update/hardskills', methods=['GET', 'POST'])
@jwt_required()
def profile_update_hardskills():
    return update_profile_data(request, get_jwt_identity(), Students, 'hardskills')


@app.route('/student/profile-update/softskills', methods=['GET', 'POST'])
@jwt_required()
def profile_update_softskills():
    return update_profile_data(request, get_jwt_identity(), Students, 'softskills')


@app.route('/student/profile-update/job', methods=['GET', 'POST'])
@jwt_required()
def profile_update_job():
    return update_profile_data(request, get_jwt_identity(), Students, 'job')


@app.route('/student/profile-update/settings', methods=['GET', 'POST'])
@jwt_required()
def profile_update_settings():
    try:
        return jsonify({'message': 'Not implemented'}), 500
    except:
        return jsonify({'message': 'Not implemented'}), 500

# ========================================================================================
#   End of profile update
# ========================================================================================

"""/admin/companies/<company>/delete

/admin/companies/<company>/edit
/admin/companies/<company>/add-employee
"""

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
            companies = [get_specific_data(company, 'admin-companies', get_raw=True) for company in companies]
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
            special_id = '123abc'
            company_users = data['company_users']

            if Companies.query.filter_by(company_name=company_name).first():
                return jsonify({'message': 'Company already exists'}), 400

            company = Companies(company_name, special_id, company_users)
            db.session.add(company)
            db.session.commit()
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

            return jsonify(get_specific_data(company, 'admin-companies', get_raw=True)), 200

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


# Admin gets all the students' data (TODO: Only give the students in batches of 20 for example, aka paging)
@app.route('/admin/student', methods=['GET'])
@jwt_required()
def admin_test():
    try:
        jwt_identity = get_jwt_identity()
        user_type = jwt_identity['user_type']

        if user_type != 'admin':
            return jsonify({'message': 'You are not an administrator'}), 400

        students = Students.query.all()
        students = [get_specific_data(student, 'admin-test-students', get_raw=True) for student in students]
        return jsonify({'students': students}), 200
    except Exception as e:
        print(e)
        return jsonify({'message': 'Something went wrong'}), 500


if __name__ == '__main__':
    app.run(debug=True)