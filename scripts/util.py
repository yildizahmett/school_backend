from flask import Flask, jsonify
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, text
import os
import json
from random import randint
from datetime import datetime, timedelta
import logging
import random
import string
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pika


TOKEN_EXPIRE_TIME = 2 # HOURS
app = Flask(__name__)
app.config.from_pyfile('config.cfg')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=TOKEN_EXPIRE_TIME)

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["20000 per hour", "3000 per minute"],
    storage_uri = app.config['RATELIMIT_STORAGE_URI'],
    key_prefix='UPS'
)

bcrypt = Bcrypt(app)
jwt = JWTManager(app)
db = SQLAlchemy(app)
engine = db.create_engine(app.config['SQLALCHEMY_DATABASE_URI'], engine_opts={'pool_size': 20, 'pool_recycle': 3600})
CORS(app)

format = '| %(asctime)s | %(funcName)s: %(lineno)d | %(message)s | %(levelname)s'
logging.basicConfig(format=format, 
                    level=logging.INFO, 
                    datefmt='%d/%b/%Y | %H:%M:%S',
                    handlers=[
                        logging.FileHandler("debug.log"),
                        logging.StreamHandler()
                    ])

REPORTING_MAILS = ["yildizah@mef.edu.tr", "yildizahmet2009@gmail.com", "kayake@mef.edu.tr", "kaya.kerrem@gmail.com", "alperensayar@gmail.com", "upschoolplatform@gmail.com"]

SAFE_TALENT_COLUMNS = ['id', 'job_title', 'highest_education', 'highest_education_grad_date', 'highest_education_department', 'workplace_type', 'comp_skills', 'onsite_city', 'languages']
UNSAFE_TALENT_COLUMNS = ['id', 'name', 'surname', 'email', 'phone', 'job_title', 'highest_education', 'highest_education_grad_date', 'highest_education_department', 'workplace_type', 'comp_skills', 'onsite_city', 'languages']

EMPLOYEE_EDIT_CHANGEABLE_FIELDS = ['name', 'surname', 'phone']

def post_search_talent(selected_filter, filtered_by):
    if len(selected_filter.keys()) < 1:
        return
    if 'salary_min' in selected_filter:
        del selected_filter['salary_min']
    if 'salary_max' in selected_filter:
        del selected_filter['salary_max']

    connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
    channel = connection.channel()
    channel.queue_declare(queue='search_logging')
    body = {"selected_filter": selected_filter, "filtered_by": filtered_by}
    channel.basic_publish(exchange='', routing_key='search_logging', body=str(body))
    connection.close()

def search_talent_log(selected_filter, filtered_by):
    date = datetime.now()
    date = date.strftime('%Y-%m-%d %H:%M:%S')
    query = f'insert into search(filter_content, filter_type, filtered_by, filter_date) values '
    for key, value in selected_filter.items():
        for v in value:
            query += f'(\'{v}\', \'{key}\', {filtered_by}, \'{date}\'),'
    query = query[:-1]
    query += ";"

    with engine.connect() as con:
        con.execute(query)
        con.close()

def student_mail_queue(emails, body, subject):
    if not isinstance(emails, list):
        return
    
    if len(emails) < 1:
        return

    connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
    channel = connection.channel()
    channel.queue_declare(queue='student_mail_queue')
    for email in emails:
        mail = {"email": email, "body": body, "subject": subject}
        channel.basic_publish(exchange='', routing_key='student_mail_sending', body=str(mail))
    connection.close()

def employee_mail_queue(emails, body, subject):
    if not isinstance(emails, list):
        return
    
    if len(emails) < 1:
        return

    connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
    channel = connection.channel()
    channel.queue_declare(queue='employee_mail_queue')
    for email in emails:
        mail = {"email": email, "body": body, "subject": subject}
        channel.basic_publish(exchange='', routing_key='employee_mail_sending', body=str(mail))
    connection.close()

def search_statistics(filter_type):
    additional_str = ''
    if filter_type == 'onsite_city':
        additional_str = ' and not filter_content = \'All\' '

    query = f'''select filter_content, count(filter_content) from search
                where filter_type = '{filter_type}' {additional_str} group by filter_content
                order by 2 desc limit 5'''

    with engine.connect() as con:
        result = con.execute(query)
        con.close()
    return [dict(row) for row in result.fetchall()]

def program_based_student_rates():
    query = """
            select 
                case when z.program_name is null then p.program_name else z.program_name end,
                case when sign_up is null then 0 else sign_up end, 
                case when invite is null then 0 else invite end, 
                case when profile_complete is null then 0 else profile_complete end
            from 
                (select program_name, count(program_name) as sign_up, sum(case profile_complete when True then 1 else 0 end) as profile_complete
            from 
                (select id, profile_complete, json_array_elements(school_programs) ->> 'program_name' as program_name from students) as t
            group by program_name) z
            full join 
                (select program_name, count(program_name) as invite
                from 
                    (select id, unnest(program_names) as program_name from temps) k
            group by program_name) p on z.program_name = p.program_name
            """

    with engine.connect() as con:
        result = con.execute(query)
        con.close()
    
    return [dict(row) for row in result.fetchall()]

def company_based_employee_rates():
    query = """
            select U.company_name, U.invites,
            case when sign_up is null then 0 else sign_up end sign_up,
            case when tc_accept is null then 0 else tc_accept end tc_accept 
            from (select K.*, D.sign_up, D.tc_accept 
                from (select company_name, array_length(company_users, 1) as invites from companies where is_active = True) K
            left join (select company_name, count(*) as sign_up, 
                    sum(case t_c when True then 1 else 0 end) as tc_accept 
            from employees where is_active = True group by company_name) D on K.company_name = D.company_name) U
            """

    with engine.connect() as con:
        result = con.execute(query)
        con.close()

    return [dict(row) for row in result.fetchall()]

def get_employment_rate():
    query = text(f'''select grad_status, count(grad_status) from students
                     where grad_status is not null and is_active = True
                     group by grad_status''')

    with engine.connect() as con:
        result = con.execute(query)
        con.close()

    return [dict(row) for row in result.fetchall()]

def general_select_count(table_name, selected_filter = None):
    where_query = ''
    if selected_filter:
        where_query = ' where '
        for key, value in selected_filter.items():
            where_query += f'{key} = {value} and '
        where_query = where_query[:-4]

    query = text(f'select count(*) from {table_name} {where_query}')
    with engine.connect() as con:
        result = con.execute(query)
        con.close()
    return result.fetchone()[0]

def company_invite_total():
    query = text('select sum(array_length(company_users, 1)) from companies')
    with engine.connect() as con:
        result = con.execute(query)
        con.close()
    return result.fetchone()[0]

def get_programs():
    query = text(f'select * from programs')
    with engine.connect() as con:
        result = con.execute(query)
        con.close()
    return [dict(row) for row in result.fetchall()]

def get_companies():
    query = text(f'select id, company_name, company_users, special_id from companies where is_active = true')
    with engine.connect() as con:
        result = con.execute(query)
        con.close()
    return [dict(row) for row in result.fetchall()]

def get_my_favourites(employee_id, t_c):
    query = text(f'''select {str(select_fav(t_c)).replace('[', '').replace(']', '').replace("'", '')} from students
                     where students.id in (select student_id from favourites where employee_id = {employee_id}) 
                     and students.is_active = True''')
    
    with engine.connect() as con:
        result = con.execute(query)
        con.close()

    return [dict(row) for row in result.fetchall()]

def get_favourited_student_ids(employee_id):
    query = text(f'select student_id from favourites where employee_id = {employee_id}')
    with engine.connect() as con:
        result = con.execute(query)
        con.close()
    return [row[0] for row in result.fetchall()]

def update_company_name(new_company_name, old_company_name):
    company_name_query = text(f"update companies set company_name = '{new_company_name}' where company_name = '{old_company_name}'")
    query = f'update employees set company_name = \'{new_company_name}\' where company_name = \'{old_company_name}\''

    with engine.connect() as con:
        con.execute(company_name_query)
        con.execute(query)
        con.close()

def update_is_active_company(company_id):
    fav_query = text(f"update favourites set is_active = false, passive_date = NOW() where company_id = {company_id}")
    employee_query = text(f"update employees set is_active = false, passive_date = NOW() where company_id = {company_id}")
    company_query = text(f"update companies set is_active = false, passive_date = NOW() where id = {company_id}")

    with engine.connect() as con:
        con.execute(fav_query)
        con.execute(employee_query)
        con.execute(company_query)
        con.close()

def update_is_activate_employees(employee_ids):
    fav_query = text(f"update favourites set is_active = false, passive_date = NOW() where employee_id in {str(employee_ids).replace('[', '(').replace(']', ')')}")
    employee_query = text(f"update employees set is_active = false, passive_date = NOW() where id in {str(employee_ids).replace('[', '(').replace(']', ')')}")

    with engine.connect() as con:
        con.execute(fav_query)
        con.execute(employee_query)
        con.close()

def update_is_activate_students(student_ids):
    fav_query = text(f"update favourites set is_active = false, passive_date = NOW() where student_id in {str(student_ids).replace('[', '(').replace(']', ')')}")
    student_query = text(f"update students set is_active = false, passive_date = NOW() where id in {str(student_ids).replace('[', '(').replace(']', ')')}")

    with engine.connect() as con:
        con.execute(fav_query)
        con.execute(student_query)
        con.close()

def get_fav_amount(is_student=False, is_employee=False):
    if is_student:
        exec_str = 'student_id'
    elif is_employee:
        exec_str = 'employee_id'
    else:
        return None

    query = text(f'select {exec_str}, count({exec_str}) from favourites where is_active = true group by {exec_str}')
    with engine.connect() as con:
        result = con.execute(query)
        con.close()
    return dict(result.fetchall())
    
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


def db_filter_admin(selected_table_name, selected_filter, to_sort, is_ascending, limit, offset, selected_columns="*"):
    if isinstance(selected_columns, list):
        selected_columns = ','.join(selected_columns)

    if selected_table_name == 'students':
        if "program_name" in selected_filter.keys() and len(selected_filter["program_name"]) > 0:
            exec_str = f"select {selected_columns} from {selected_table_name} t, json_array_elements(t.school_programs) as obj where is_active = true and "
        else:
            exec_str = f"select {selected_columns} from {selected_table_name} t where is_active = true and "
    else:
        exec_str = f"select {selected_columns} from {selected_table_name} where is_active = true and "

    for key, value in selected_filter.items():
        if value == []:
            continue
        if key == 'program_name':
            exec_str += "obj->> 'program_name' IN ("
            for v in value:
                exec_str += f"'{v}',"
            exec_str = exec_str[:-1] + ") and "
        elif key == 'grad_date':
            exec_str += "highest_education_grad_date IN ("
            for v in value:
                exec_str += f"'{v}',"
            exec_str = exec_str[:-1] + ") and "
        elif key == 'grad_status':
            exec_str += "grad_status IN ("
            for v in value:
                exec_str += f"'{v}',"
            exec_str = exec_str[:-1] + ") and "
        elif key == 'company_name':
            exec_str += "company_name IN ("
            for v in value:
                exec_str += f"'{v}',"
            exec_str = exec_str[:-1] + ") and "
        elif key == 't_c':
            exec_str += f"t_c = '{value[0]}' and "
        elif key == 'profile_complete':
            exec_str += f"profile_complete = '{value[0]}' and "

    exec_str = exec_str[:-5]

    exec_str += f" order by {to_sort} {'asc' if is_ascending else 'desc' }"
    exec_str += f" limit {limit} offset {offset}"
    
    with engine.connect() as con:
        result = con.execute(text(exec_str))
        data = result.fetchall()
        data = [d._asdict() for d in data]
        con.close()

    return data

def db_filter_admin_count(selected_table_name, selected_filter):
    if selected_table_name == 'students':
        if "program_name" in selected_filter.keys() and len(selected_filter["program_name"]) > 0:
            exec_str = f"select count(*) from {selected_table_name} t, json_array_elements(t.school_programs) as obj where is_active = true and "
        else:
            exec_str = f"select count(*) from {selected_table_name} where is_active = true and "
    else:
        exec_str = f"select count(*) from {selected_table_name} where is_active = true and "

    for key, value in selected_filter.items():
        if value == []:
            continue
        if key == 'program_name':
            exec_str += "obj->> 'program_name' IN ("
            for v in value:
                exec_str += f"'{v}',"
            exec_str = exec_str[:-1] + ") and "
        elif key == 'grad_date':
            exec_str += "highest_education_grad_date IN ("
            for v in value:
                exec_str += f"'{v}',"
            exec_str = exec_str[:-1] + ") and "
        elif key == 'grad_status':
            exec_str += "grad_status IN ("
            for v in value:
                exec_str += f"'{v}',"
            exec_str = exec_str[:-1] + ") and "
        elif key == 'company_name':
            exec_str += "company_name IN ("
            for v in value:
                exec_str += f"'{v}',"
            exec_str = exec_str[:-1] + ") and "
        elif key == 't_c':
            exec_str += f"t_c = '{value[0]}' and "
        elif key == 'profile_complete':
            exec_str += f"profile_complete = '{value[0]}' and "

    exec_str = exec_str[:-5]

    with engine.connect() as con:
        result = con.execute(text(exec_str))
        data = result.fetchone()
        con.close()

    return data[0]


def db_filter_employee(selected_table_name, selected_filter, to_sort, is_ascending, limit, offset, selected_columns="*"):
    if isinstance(selected_columns, list):
        selected_columns = ','.join(selected_columns)

    if ('languages' in selected_filter.keys() and len(selected_filter["languages"]) > 0) or ('proficiency' in selected_filter.keys() and len(selected_filter["proficiency"]) > 0):
        exec_str = f"select {selected_columns} from {selected_table_name} t, json_array_elements(t.languages) as obj where is_active = true and "
    else:
        exec_str = f"select {selected_columns} from {selected_table_name} t where is_active = true and "
    for key, value in selected_filter.items():
        if value == []:
            continue
        exec_str += "("
        if key == 'comp_skills':
            for i in value:
                exec_str += "'" + i + "' = ANY(comp_skills) or "
            exec_str = exec_str[:-4] + ") and "

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
            for i in value:
                exec_str += "'" + i + "' = ANY(onsite_city) or "
            exec_str = exec_str[:-4] + ") and "

        else:
            for i in value:
                if isinstance(i, str):
                    exec_str += key + " = '" + str(i) + "' or "
                else:
                    exec_str += key + " = " + str(i) + " or "
            exec_str = exec_str[:-4] + ") and "

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

    if ('languages' in selected_filter.keys() and len(selected_filter["languages"]) > 0) or ('proficiency' in selected_filter.keys() and len(selected_filter["proficiency"]) > 0):
        exec_str = f"select count(*) from {selected_table_name} t, json_array_elements(t.languages) as obj where is_active = true and "
    else:
        exec_str = f"select count(*) from {selected_table_name} t where is_active = true and "
    for key, value in selected_filter.items():
        if value == []:
            continue
        exec_str += "("
        if key == 'comp_skills':
            for i in value:
                exec_str += "'" + i + "' = ANY(comp_skills) or "
            exec_str = exec_str[:-4] + ") and "

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
            for i in value:
                exec_str += "'" + i + "' = ANY(onsite_city) or "
            exec_str = exec_str[:-4] + ") and "
        
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


def db_get_student_for_fav(employee_id):
    exec_str = f"""select students.id, students.name, students.surname, students.email, students.phone, students.school_programs
                  from students
                  inner join favourites on students.id = favourites.student_id 
                  where favourites.employee_id = {employee_id} and students.is_active = true and favourites.is_active = true"""

    with engine.connect() as con:
        result = con.execute(text(exec_str))
        data = result.fetchall()
        data = [d._asdict() for d in data]
        con.close()
    
    return data

def db_count_student_fav(employee_id):
    exec_str = f"""select count(*)
                  from students
                  inner join favourites on students.id = favourites.student_id 
                  where favourites.employee_id = {employee_id} and favourites.is_active = true and students.is_active = true"""

    with engine.connect() as con:
        result = con.execute(text(exec_str))
        data = result.fetchone()
        con.close()

    return data[0]

def db_get_employee_for_fav(student_id):
    exec_str = f"""select employees.id, employees.name, employees.surname, employees.email, employees.phone, employees.company_name
                   from employees
                   inner join favourites on employees.id = favourites.employee_id 
                   where favourites.student_id = {student_id} and favourites.is_active = true and employees.is_active = true"""

    with engine.connect() as con:
        result = con.execute(text(exec_str))
        data = result.fetchall()
        data = [d._asdict() for d in data]
        con.close()

    return data

def db_count_employee_fav(student_id):
    exec_str = f"""select count(*)
                   from employees
                   inner join favourites on employees.id = favourites.employee_id 
                   where favourites.student_id = {student_id} and favourites.is_active = true and employees.is_active = true"""

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

FRONTEND_LINK = 'https://school-frontend.vercel.app'

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
        logging.warning(f'User: {member.email} | {log_body}')
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
        logging.warning(f'User: {member.email} | {log_body}')
        return 'ERROR: Something went wrong while changing data.'

def update_profile_data(request, jwt_identitiy, Members, needed_data):
    try:
        message = ''
        user_type = jwt_identitiy['user_type']
        
        if user_type != 'student':
            log_body = f'update_profile_data > ERROR : User type is not student'
            logging.warning(f'User: {email} | {log_body}')
            return jsonify({'message': 'You are not a student'}), 401

        user_type = jwt_identitiy['user_type']
        email = jwt_identitiy['email']

        try:
            
            student = Members.query.filter_by(email=email, is_active=True).first()
            if not student:
                log_body = f'update_profile_data > ERROR : Student not found'
                logging.warning(f'User: {email} | {log_body}')
                return jsonify({'message': 'Student does not exist'}), 400

            # Check student info is completed
            student_info = student.to_dict()
            if (not student.profile_complete) and all(student_info.values()) and all(student_info["school_programs"][0].values()):
                setattr(student, 'profile_complete', True)               

            if request.method == 'GET':
                requested_data = get_specific_data(student, needed_data)
                return requested_data

            elif request.method == 'POST':
                message += update_table_data(request.get_json(), student, db)
                log_body = f'update_profile_data > SUCCESS : {message}'
                logging.info(f'User: {email} | {log_body}')
                return jsonify({'message': 'User updated successfully. ' + message}), 200

        except Exception as e:
            logging.info(f'User: {email} | Update_profile_data : Request Operations : ERROR : ' + repr(e))
            return jsonify({'message': 'Something went wrong in request operations'}), 500

    except Exception as e:
        log_body = f'update_profile_data > ERROR : {repr(e)}'
        logging.warning(f'User: {email} | {log_body}')
        return jsonify({'message': 'Something went wrong'}), 500

def sort_by_key(data, param):
    return sorted(data, key=lambda x: x[param])