from flask import request, jsonify
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity
from datetime import datetime, timedelta
import random
import json

from scripts.util import app, bcrypt, jwt, db, Students, Employees, Companies, Favourites

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

        return jsonify({'message': 'User created successfully'}), 201
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
            return jsonify({'message': 'Incorrect password'}), 400
        
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

        return jsonify({'message': 'User created successfully'}), 201
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
            return jsonify({'message': 'Incorrect password'}), 400
    except:
        return jsonify({'message': 'Something went wrong'}), 500


@app.route('/student-profile-update', methods=['GET', 'POST'])
@jwt_required()
def student_profile_update():
    try:
        jwt_identitiy = get_jwt_identity()
        user_type = jwt_identitiy['user_type']
        email = jwt_identitiy['email']

        message = ""

        if user_type != 'student' and user_type != 'temp_student':
            return jsonify({'message': 'You are not a student'}), 400

        try:
            student = Students.query.filter_by(email=email).first()
            if request.method == 'GET':
                return jsonify(student.to_dict()), 200

            elif request.method == 'POST':
                data = request.get_json()

                if 'password' in data.keys():
                    hashed_password = bcrypt.generate_password_hash(data["password"]).decode('utf-8')
                    setattr(student, "password", hashed_password)
                    # delete password from data
                    del data["password"]

                for key, value in data.items():
                    try:
                        setattr(student, key, value)
                    except Exception as e:
                        print(e)
                        message += 'but the key ' + key + ' is not in the model '
                
                db.session.commit()
                return jsonify({'message': 'User updated successfully' + message}), 200

        except:
            return jsonify({'message': 'Something went wrong in request operations'}), 500

    except:
        return jsonify({'message': 'Something went wrong'}), 500
            




"""----------------------------------------------------------------------------------------------------
-------------------------------------------------------------------------------------------------------"""

@app.route('/company-register', methods=['POST'])
def company_register():
    data = request.get_json()
    company_name = data['company_name']
    special_id = data['special_id']
    company_users = data['company_users']

    if Companies.query.filter_by(company_name=company_name).first():
        return jsonify({'message': 'Company already exists'}), 400

    company = Companies(company_name, special_id, company_users)
    db.session.add(company)
    db.session.commit()
    return jsonify({'message': 'Company created successfully'}), 201


@app.route('/student-dashboard', methods=['GET'])
@jwt_required()
def student_dashboard():
    token_identity = get_jwt_identity()
    user_type = token_identity['user_type']
    email = token_identity['email']
    if user_type != 'student':
        return jsonify({'message': 'You are not a student'}), 400
    
    user = Students.query.filter_by(email=email).first()
    return jsonify({'email': user.email}), 200

if __name__ == '__main__':
    app.run(debug=True)