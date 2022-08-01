from flask import Flask, jsonify
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, text
import os
import json
from random import randint
from datetime import timedelta
import logging
import random
import string

TOKEN_EXPIRE_TIME = 2 # HOURS
app = Flask(__name__)
app.config.from_pyfile('config.cfg')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=TOKEN_EXPIRE_TIME)

bcrypt = Bcrypt(app)
jwt = JWTManager(app)
db = SQLAlchemy(app)
engine = db.create_engine(app.config['SQLALCHEMY_DATABASE_URI'], engine_opts={'pool_size': 20, 'pool_recycle': 3600})
CORS(app)

def db_filter(selected_table_name, selected_filter, to_sort, is_ascending, start, end):
    if selected_filter == {}:
        exec_str = f"select * from {selected_table_name} "
    else:
        print(selected_filter)
        if selected_table_name == 'students':
            exec_str = f"select * from {selected_table_name} t, json_array_elements(t.school_programs) as obj where "
        else:
            exec_str = f"select * from {selected_table_name} where "

        if list(selected_filter.values()) == [[], []]:
            exec_str = exec_str[:-6]

        for key, value in selected_filter.items():
            if value != [] and key == 'program_name':
                exec_str += "obj->> 'program_name' IN ("
                for v in value:
                    exec_str += f"'{v}',"
                exec_str = exec_str[:-1] + ")"
            elif value != [] and key == 'grad_date':
                print()
                # grad_date to come
            elif value != [] and key == 'company_name':
                exec_str += "company_name IN ("
                for v in value:
                    exec_str += f"'{v}',"
                exec_str = exec_str[:-1] + ")"
            elif value != [] and key == 't_c':
                exec_str += f"t_c = '{value[0]}'"
                
        
        

        # for key, value in selected_filter.items():
        #     exec_str += "("
        #     for i in value:
        #         if isinstance(i, str):
        #             exec_str += key + " = '" + str(i) + "' or "
        #         else:
        #             exec_str += key + " = " + str(i) + " or "
        #     exec_str = exec_str[:-4] + ") and "
        # exec_str = exec_str[:-5]

    exec_str += f" order by {to_sort} {'asc' if is_ascending else 'desc' }"
    
    with engine.connect() as con:
        result = con.execute(text(exec_str))
        data = result.fetchall()
        data = [d._asdict() for d in data]
        emails = [d['email'] for d in data]
        new_data = [data[0]]
        for user in data:
            if not user['email'] in [em['email'] for em in new_data]:
                new_data.append(user)


        con.close()

    return new_data[start-1:end]

def json_to_dict(filename):
    with open(filename, 'r') as j:
        data = json.load(j)
    return data

data_category = json_to_dict('./json_files/category.json')

# Data Category Constants
DC_AD_STUDENT       = 'admin-students'
DC_AD_COMPANIES     = 'admin-companies'
DC_AD_EMPLOYEES     = 'admin-employees'
DC_ST_GENERAL       = 'general'
DC_ST_ACTIVITIES    = 'activities'
DC_ST_HARDSKILLS    = 'hardskills'
DC_ST_JOB           = 'job'

FRONTEND_LINK = 'http://localhost:3000'

format = '| %(asctime)s | %(funcName)s: %(lineno)d | %(message)s | %(levelname)s'
logging.basicConfig(format=format, level=logging.INFO, datefmt='%d/%b/%Y | %H:%M:%S')
# filename='current.log', filemode='a', # add this code to the inside of basicConfig to store logs in a file instead of printing to the terminal

"""
def random_id_generator(length):
    # Primitive Version
    code = ''
    for x in range(length):
        code += str(randint(0, 9))
        code += chr(randint(65, 90))
    return code
"""

def random_id_generator(size=8, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


def get_specific_data(member, needed_data, get_raw=False):
    try:
        prior_data = member.to_dict()

        final_data = {key: val for key, val in prior_data.items() if (key in data_category[needed_data])}

        if get_raw:
            return final_data
        return jsonify(final_data), 200
    except Exception as e:
        log_body = f'get_specific_data > ERROR : {repr(e)}'
        logging.warning(f'{log_body}')
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
        log_body = f'update_table_data > ERROR : {repr(e)}'
        logging.warning(f'{log_body}')
        return 'ERROR: Something went wrong while changing data.'

def update_profile_data(request, jwt_identitiy, Members, needed_data):
    try:
        user_type = jwt_identitiy['user_type']
        email = jwt_identitiy['email']

        message = ''

        if user_type != 'student':
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
            logging.info('update_profile_data : Request Operations : ERROR : ' + repr(e))
            return jsonify({'message': 'Something went wrong in request operations'}), 500

    except Exception as e:
        log_body = f'update_profile_data > ERROR : {repr(e)}'
        logging.warning(f'IP: {request.remote_addr} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500