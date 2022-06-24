from flask import request, jsonify
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity
from datetime import datetime, timedelta
import os
import random
import json
from scripts.util import app, bcrypt, jwt, db, get_specific_data, update_table_data, update_profile_data
from scripts.models import Companies, Employees, Favourites, Students


@app.route('/student-register', methods=['POST'])
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
        user = Students(email, hashed_password, name, surname)
        db.session.add(user)
        db.session.commit()

        return jsonify({'message': 'User created successfully'}), 200
    except:
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/student-login', methods=['POST'])
def student_login():
    try:
        data = request.get_json()
        email = data['email']
        password = data['password']

        student = Students.query.filter_by(email=email).first()

        if not student:
            return jsonify({'message': 'Student does not exist'}), 400

        if student.is_temp == True:
            token_identity = {'user_type': 'temp_student', 'email': email}
        else:
            token_identity = {'user_type': 'student', 'email': email}

        if bcrypt.check_password_hash(student.password, password):
            access_token = create_access_token(identity=token_identity)
            return jsonify({'access_token': access_token}), 200
        else:
            return jsonify({'message': 'Incorrect password or email'}), 400
        
    except:
        return jsonify({'message': 'Something went wrong'}), 500
    

@app.route('/employee-register', methods=['POST'])
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
    

@app.route('/employee-login', methods=['POST'])
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

@app.route('/profile-update', methods=['GET', 'POST'])
@jwt_required()
def profile_update_general():
    return update_profile_data(request, get_jwt_identity(), Students, 'general')


@app.route('/profile-update/activities', methods=['GET', 'POST'])
@jwt_required()
def profile_update_activities():
    return update_profile_data(request, get_jwt_identity(), Students, 'activities')


@app.route('/profile-update/hardskills', methods=['GET', 'POST'])
@jwt_required()
def profile_update_hardskills():
    return update_profile_data(request, get_jwt_identity(), Students, 'hardskills')


@app.route('/profile-update/softskills', methods=['GET', 'POST'])
@jwt_required()
def profile_update_softskills():
    return update_profile_data(request, get_jwt_identity(), Students, 'softskills')


@app.route('/profile-update/job', methods=['GET', 'POST'])
@jwt_required()
def profile_update_job():
    return update_profile_data(request, get_jwt_identity(), Students, 'job')


@app.route('/profile-update/settings', methods=['GET', 'POST'])
@jwt_required()
def profile_update_settings():
    try:
        pass
    except:
        pass

# ========================================================================================
#   End of profile update
# ========================================================================================


@app.route('/admin/company-register', methods=['POST'])
def company_register():
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


@app.route('/admin/company-add-employee', methods=['POST'])
def company_add_user():
    try:
        data = request.get_json()
        company_name = data['company_name']
        new_employees = data['company_users']
        
        try:
            company = Companies.query.filter_by(company_name=company_name).first()
            final_employees = company.company_users + new_employees
            
            setattr(company, 'company_users', final_employees)
            db.session.commit()
            return jsonify({'message': 'Employees updated succesfully. Current: ' + str(final_employees)}), 200
        except Exception as e:
            print(e)
            return jsonify({'message': 'Something went wrong in request operations'}), 500

    except Exception as e:
        print(e)
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/super-secret-admin-login', methods=['POST'])
def administrator_login():
    try:
        data = request.get_json()
        email = data['email']
        password = data['password']

        admin = None

        with open('admins/admin1.json', 'r') as j:
            admin = json.load(j)
        admin = dict(admin)

        if email != admin['email'] or admin['password'] != password:
            return jsonify({'message': 'Incorrect password or email'}), 400

        print(admin)
        
        return jsonify({'message': 'Admin login successful'}), 200
    except Exception as e:
        print(e)
        return jsonify({'message': 'Something went wrong'}), 500


# This code shall be removed later!
@app.route('/student-dashboard', methods=['GET'])
@jwt_required()
def student_dashboard():
    try:
        token_identity = get_jwt_identity()
        user_type = token_identity['user_type']
        email = token_identity['email']
        if user_type != 'student':
            return jsonify({'message': 'You are not a student'}), 400
        
        user = Students.query.filter_by(email=email).first()
        return jsonify({'email': user.email}), 200
    except Exception as e:
        print(e)
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/admin/students', methods=['GET'])
def admin_test():
    try:
        students = Students.query.all()
        students = [get_specific_data(student, 'admin-test-students', get_raw=True) for student in students]
        return jsonify({'students': students}), 200
    except Exception as e:
        print(e)
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/admin/companies', methods=['GET'])
def admin_test_companies():
    try:
        companies = Companies.query.all()
        companies = [get_specific_data(company, 'admin-test-companies', get_raw=True) for company in companies]
        return jsonify({'companies': companies}), 200
    except Exception as e:
        print(e)
        return jsonify({'message': 'Something went wrong'}), 500


if __name__ == '__main__':
    app.run(debug=True)