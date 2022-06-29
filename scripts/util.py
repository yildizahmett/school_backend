from flask import Flask, jsonify
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy
import os
import json
from random import randint
from datetime import timedelta

TOKEN_EXPIRE_TIME = 2 # HOURS
app = Flask(__name__)
app.config.from_pyfile('config.cfg')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=TOKEN_EXPIRE_TIME)

bcrypt = Bcrypt(app)
jwt = JWTManager(app)
db = SQLAlchemy(app)
CORS(app)


def json_to_dict(filename):
    with open(filename, 'r') as j:
        data = json.load(j)
    return data

data_category = json_to_dict('./json_files/category.json')

# Data Category Constants
DC_AD_STUDENT       = 'admin-students'
DC_AD_COMPANIES     = 'admin-companies'
DC_ST_GENERAL       = 'general'
DC_ST_ACTIVITIES    = 'activities'
DC_ST_HARDSKILLS    = 'hardskills'
DC_ST_SOFTSKILLS    = 'softskills'
DC_ST_JOB           = 'job'


def random_id_generator(length):
    # Primitive Version
    code = ''

    for x in range(length):
        code += str(randint(0, 9))
        code += chr(randint(65, 90))

    return code


def get_specific_data(member, needed_data, get_raw=False):
    try:
        prior_data = member.to_dict()

        final_data = {key: val for key, val in prior_data.items() if (key in data_category[needed_data])}

        if get_raw:
            return final_data
        return jsonify(final_data), 200
    except Exception as e:
        print(e)
        return jsonify({'message': 'Something went wrong'}), 500

def update_table_data(data, member, db):
    try:
        if 'password' in data.keys():
            # delete password from data
            del data["password"]

        message = ''

        for key, value in data.items():
            try:
                setattr(member, key, value)
            except Exception as e:
                print(e)
                message += 'But the key ' + key + ' is not in the model. '

        db.session.commit()
        return message
    except Exception as e:
        print(e)
        return 'ERROR: Something went wrong while changing data.'

def update_profile_data(request, jwt_identitiy, Members, needed_data):
    try:
        user_type = jwt_identitiy['user_type']
        email = jwt_identitiy['email']

        message = ''

        if user_type != 'student' and user_type != 'temp_student':
            return jsonify({'message': 'You are not a student'}), 400

        try:
            
            student = Members.query.filter_by(email=email).first()
            if request.method == 'GET':
                requested_data = get_specific_data(student, needed_data)
                return requested_data

            elif request.method == 'POST':
                message += update_table_data(request.get_json(), student, db)
                return jsonify({'message': 'User updated successfully. ' + message}), 200

        except Exception as e:
            print(e)
            return jsonify({'message': 'Something went wrong in request operations'}), 500

    except Exception as e:
        print(e)
        return jsonify({'message': 'Something went wrong'}), 500