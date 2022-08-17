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

SAFE_TALENT_COLUMNS = ['id', 'job_title', 'highest_education', 'highest_education_grad_date', 'highest_education_department', 'workplace_type', 'comp_skills', 'onsite_city', 'languages']
UNSAFE_TALENT_COLUMNS = ['id', 'name', 'surname', 'email', 'phone', 'job_title', 'highest_education', 'highest_education_grad_date', 'highest_education_department', 'workplace_type', 'comp_skills', 'onsite_city', 'languages']

def check_t_c_date(employee):
    pass

def select_fav(t_c):
    if not t_c:
        return ['id', 'job_title', 'highest_education', 'highest_education_grad_date', 'highest_education_department', 'workplace_type', 'comp_skills', 'onsite_city', 'languages']
    return ['id', 'name', 'surname', 'email', 'phone', 'job_title', 'highest_education', 'highest_education_grad_date', 'highest_education_department', 'workplace_type', 'comp_skills', 'onsite_city', 'languages']

def select_std(t_c):
    if not t_c:
        return ['id', 'job_title', 'workplace_type', 'onsite_city', 'comp_skills', 'educations', 'school_programs', 'projects', 'languages', 'certificates']
    return ['id', 'name', 'surname', 'email', 'phone', 'job_title', 'workplace_type', 'onsite_city', 'summary', 'comp_skills', 'experiences', 'educations', 'school_programs', 'projects', 'languages', 'certificates', 'volunteer', 'linkedin', 'github', 'medium']

def db_filter_admin(selected_table_name, selected_filter, to_sort, is_ascending, start, end, selected_columns="*"):
    if isinstance(selected_columns, list):
        selected_columns = ','.join(selected_columns)

    if selected_filter == {}:
        exec_str = f"select {selected_columns} from {selected_table_name} "
    else:
        if selected_table_name == 'students':
            exec_str = f"select {selected_columns} from {selected_table_name} t, json_array_elements(t.school_programs) as obj where "
        else:
            exec_str = f"select {selected_columns} from {selected_table_name} where "
        print(selected_table_name)
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
                exec_str = exec_str[:-1] + ") and "
            elif value != [] and key == 't_c':
                exec_str += f"t_c = '{value[0]}' and "
        if selected_table_name != 'students' and list(selected_filter.values()) != [[], []]:
            exec_str = exec_str[:-4]

    exec_str += f" order by {to_sort} {'asc' if is_ascending else 'desc' }"
    
    # Musait zamanda bakkkkkkkkkkkkkkkkk
    with engine.connect() as con:
        result = con.execute(text(exec_str))
        data = result.fetchall()
        data = [d._asdict() for d in data]
        emails = [d['email'] for d in data]
        
        if data != []:
            new_data = [data[0]]
            for user in data:
                if not user['email'] in [em['email'] for em in new_data]:
                    new_data.append(user)
            new_data = new_data[start-1:end]
        else:
            new_data = []
        con.close()

    return new_data

def db_filter_employee(selected_table_name, selected_filter, to_sort, is_ascending, limit, offset, selected_columns="*", favourite_students=[]):
    if isinstance(selected_columns, list):
        selected_columns = ','.join(selected_columns)

    if selected_filter == {}:
        exec_str = f"select {selected_columns} from {selected_table_name} "
        # Cant take favourite students
        if not favourite_students == []:
            exec_str += " where students.id NOT IN ("
            for i in favourite_students:
                exec_str += str(i) + ","
            exec_str = exec_str[:-1] + ") "

    else:
        exec_str = f"select {selected_columns} from {selected_table_name} t, json_array_elements(t.languages) as obj where "
        for key, value in selected_filter.items():

            exec_str += "("

            if key == 'comp_skills':
                for i in value:
                    exec_str += "'" + i + "' = ANY(comp_skills) and "
                exec_str = exec_str[:-5] + ") and "

            elif key == 'languages':
                exec_str += "obj->> 'name' IN ("
                for v in value:
                    exec_str += f"'{v}',"
                exec_str = exec_str[:-1] + ")) and "

            elif key == 'proficiency':
                exec_str += "obj->> 'level' IN ("
                for v in value:
                    exec_str += f"'{v}',"
                exec_str = exec_str[:-1] + ")) and "

            elif key == 'salary_min':
                exec_str += "salary_min > " + value + ") and "
            
            elif key == 'salary_max':
                exec_str += "salary_min < " + value + ") and "

            elif key == "onsite_city":
                exec_str += "onsite_city = '" + value + "') and "

            else:
                for i in value:
                    if isinstance(i, str):
                        exec_str += key + " = '" + str(i) + "' or "
                    else:
                        exec_str += key + " = " + str(i) + " or "
                exec_str = exec_str[:-4] + ") and "

        # Can't take favourite students
        if not favourite_students == []:
            exec_str += "t.id NOT IN ("
            for i in favourite_students:
                exec_str += str(i) + ","
            exec_str = exec_str[:-1] + ") and "

        exec_str = exec_str[:-5]

    exec_str += f" order by {to_sort} {'asc' if is_ascending else 'desc' }"
    exec_str += f" limit {limit} offset {offset}"
    
    with engine.connect() as con:
        result = con.execute(text(exec_str))
        data = result.fetchall()
        data = [d._asdict() for d in data]
        con.close()

    return data

def db_filter_student_count(selected_table_name, selected_filter):
    if selected_filter == {}:
        exec_str = f"select count(*) from {selected_table_name} "
    else:
        exec_str = f"select count(*) from {selected_table_name} t, json_array_elements(t.school_programs) as obj where "
        for key, value in selected_filter.items():

            exec_str += "("

            if key == 'comp_skills':
                for i in value:
                    exec_str += "'" + i + "' = ANY(comp_skills) and "
                exec_str = exec_str[:-5] + ") and "

            elif key == 'languages':
                exec_str += "obj->> 'name' IN ("
                for v in value:
                    exec_str += f"'{v}',"
                exec_str = exec_str[:-1] + ")) and "

            elif key == 'proficiency':
                exec_str += "obj->> 'level' IN ("
                for v in value:
                    exec_str += f"'{v}',"
                exec_str = exec_str[:-1] + ")) and "

            elif key == 'salary_min':
                exec_str += "salary_min > " + value + ") and "
            
            elif key == 'salary_max':
                exec_str += "salary_min < " + value + ") and "

            elif key == "onsite_city":
                exec_str += "onsite_city = '" + value + "') and "

            else:
                for i in value:
                    if isinstance(i, str):
                        exec_str += key + " = '" + str(i) + "' or "
                    else:
                        exec_str += key + " = " + str(i) + " or "
                exec_str = exec_str[:-4] + ") and "

        exec_str = exec_str[:-5]
    with engine.connect() as con:
        result = con.execute(text(exec_str))
        data = result.fetchone()
        con.close()

    return data[0]

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


def get_specific_data(member, needed_data, get_raw=False, direct_data=False):
    try:
        prior_data = member.to_dict()

        if direct_data:
            final_data = {key: val for key, val in prior_data.items() if (key in needed_data)}
        else:
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

                if key == 'educations':
                    sorted_educations = sort_by_key(value, 'graduation')

                    setattr(member, 'highest_education', sorted_educations[-1]['degree'])
                    setattr(member, 'highest_education_grad_date', sorted_educations[-1]['graduation'])
                    setattr(member, 'highest_education_department', sorted_educations[-1]['department'])

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

            # Check student info is completed
            student_info = student.to_dict()
            if (not student.profile_complete) and all(student_info.values()) and all(student_info["school_programs"][0].values()):
                setattr(student, 'profile_complete', True)               

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

def sort_by_key(data, param):
    return sorted(data, key=lambda x: x[param])