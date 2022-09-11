from sqlalchemy.dialects.postgresql import JSON as pg_JSON
from datetime import datetime
from scripts.util import db


class Temps(db.Model):
    __table_name__  = 'temps'
    id              = db.Column(db.Integer, primary_key=True)
    email           = db.Column(db.String(120), unique=True, nullable=False)
    program_names   = db.Column(db.ARRAY(db.String(120)), nullable=True)
    program_codes   = db.Column(db.ARRAY(db.Integer), nullable=True)
    date            = db.Column(db.DateTime, nullable=False)

    def __init__(self, email, program_names, program_codes):
        self.email = email
        self.program_names = program_names
        self.program_codes = program_codes
        self.date = datetime.now()

    def add_program(self, program_name):
        self.program_names.append(program_name)


class Students(db.Model):
    __table_name__  = 'students'
    id              = db.Column(db.Integer, primary_key=True)
    email           = db.Column(db.String(120), nullable=False)
    password        = db.Column(db.String(255), nullable=False)
    name            = db.Column(db.String(120), nullable=False)
    surname         = db.Column(db.String(120), nullable=False)
    gender          = db.Column(db.String(120), nullable=True)
    phone           = db.Column(db.String(25), nullable=True) # the length may be shortened
    summary         = db.Column(db.String(255), nullable=True)
    linkedin        = db.Column(db.String(240), nullable=True)
    github          = db.Column(db.String(240), nullable=True)
    medium          = db.Column(db.String(240), nullable=True)
    comp_skills     = db.Column(db.ARRAY(db.String(120)), nullable=True)
    hobbies         = db.Column(db.ARRAY(db.String(120)), nullable=True)
    birth_date      = db.Column(db.DateTime, nullable=True)
    job_title       = db.Column(db.String(120), nullable=True)
    city            = db.Column(db.String(120), nullable=True)
    country         = db.Column(db.String(120), nullable=True)
    educations      = db.Column(pg_JSON)
    experiences     = db.Column(pg_JSON)
    projects        = db.Column(pg_JSON)
    languages       = db.Column(pg_JSON)
    certificates    = db.Column(pg_JSON)
    school_programs = db.Column(pg_JSON)
    volunteer       = db.Column(pg_JSON)
    workplace_type  = db.Column(db.String(120), nullable=True)
    salary_min      = db.Column(db.Integer, nullable=True)
    salary_currency = db.Column(db.String(50), nullable=True)
    onsite_city     = db.Column(db.ARRAY(db.String(120)), nullable=True)
    profile_complete= db.Column(db.Boolean, nullable=False)
    job_find_time   = db.Column(db.DateTime, nullable=True)
    grad_status     = db.Column(db.String(40), nullable=True)
    grad_date       = db.Column(db.DateTime, nullable=True)
    date            = db.Column(db.DateTime, nullable=False)
    highest_education = db.Column(db.String(120), nullable=True)
    highest_education_grad_date = db.Column(db.Integer, nullable=True)
    highest_education_department = db.Column(db.String(120), nullable=True)
    updated_at = db.Column(db.DateTime, nullable=True)
    updated_by = db.Column(db.String(120), nullable=True)
    is_active = db.Column(db.Boolean, nullable=False)
    passive_date = db.Column(db.DateTime, nullable=True)

    favourites      = db.relationship('Favourites', backref='student_ref', lazy=True)

    def __init__(self, email, password, name, surname):
        self.email = email
        self.password = password
        self.name = name
        self.surname = surname
        self.profile_complete = False
        self.fav_amount = 0
        self.date = datetime.now()
        self.is_active = True

    def to_dict(self):
        return {i.name: getattr(self, i.name) for i in self.__table__.columns if i.name != 'password'}


class Companies(db.Model):
    __tablename__ = 'companies'
    id=db.Column(db.Integer,primary_key=True)
    company_name = db.Column(db.String(100), nullable=False)
    special_id = db.Column(db.String(20), unique=True)
    company_users = db.Column(db.ARRAY(db.String(100)), nullable=True)
    date = db.Column(db.DateTime, nullable=False)
    updated_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, nullable=False)
    passive_date = db.Column(db.DateTime, nullable=True)

    temp_employees = db.relationship('TempEmployees', backref='company_ref', lazy=True)
    employees = db.relationship('Employees', backref='company_ref', lazy=True)
    favourites = db.relationship('Favourites', backref='company_ref', lazy=True)

    def __init__(self, company_name, special_id, company_users):
        self.company_name = company_name
        self.special_id = special_id
        self.company_users = company_users
        self.date = datetime.now()
        self.is_active = True

    def __repr__(self):
        return f'<Company "{self.company_name}">'

    def add_user(self, user):
        self.company_users.append(user)

    def to_dict(self):
        return {i.name: getattr(self, i.name) for i in self.__table__.columns}


class TempEmployees(db.Model):
    __tablename__ = 'temp_employees'
    id=db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, nullable=False)
    passive_date = db.Column(db.DateTime, nullable=True)

    def __init__(self, email, company_id):
        self.email = email
        self.company_id = company_id
        self.date = datetime.now()
        self.is_active = True


class Employees(db.Model):
    __table_name__  = 'employees'
    id              = db.Column(db.Integer, primary_key=True)
    name            = db.Column(db.String(80), nullable=False)
    surname         = db.Column(db.String(80), nullable=False)
    email           = db.Column(db.String(120), nullable=False)
    phone           = db.Column(db.String(25), nullable=True) # the length may be shortened
    password        = db.Column(db.String(255), nullable=False)
    t_c             = db.Column(db.Boolean, nullable=True)
    t_c_date        = db.Column(db.DateTime, nullable=True)
    t_c_expire_date = db.Column(db.DateTime, nullable=True)
    duration        = db.Column(db.String(255), nullable=True)
    company_id      = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    company_name    = db.Column(db.String(100), nullable=False)
    is_company_admin= db.Column(db.Boolean, nullable=True)
    date            = db.Column(db.DateTime, nullable=False)
    updated_at      = db.Column(db.DateTime, nullable=True)
    updated_by      = db.Column(db.String(120), nullable=True)
    is_active       = db.Column(db.Boolean, nullable=False)
    passive_date    = db.Column(db.DateTime, nullable=True)

    favourites      = db.relationship('Favourites', backref='employee_ref', lazy=True)

    def __init__(self, name, surname, phone, email, password, company_id, company_name):
        self.name = name
        self.surname = surname
        self.phone = phone
        self.email = email
        self.password = password
        self.company_id = company_id
        self.company_name = company_name
        self.t_c = False
        self.duration = 0
        self.fav_amount = 0
        self.is_company_admin = False
        self.date = datetime.now()
        self.is_active = True
    
    def __repr__(self):
        return f'<Employee "{self.name} {self.surname}">'

    def to_dict(self):
        return {i.name: getattr(self, i.name) for i in self.__table__.columns if i.name != 'password'}


class Favourites(db.Model):
    __tablename__ = 'favourites'
    id=db.Column(db.Integer,primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    date = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, nullable=False)
    passive_date = db.Column(db.DateTime, nullable=True)

    def __init__(self, student_id, company_id, employee_id):
        self.student_id = student_id
        self.company_id = company_id
        self.employee_id = employee_id
        self.date = datetime.now()
        self.is_active = True


class Programs(db.Model):
    __tablename__= 'programs'
    id=db.Column(db.Integer,primary_key=True)
    program_name = db.Column(db.String(120), nullable=False)
    program_code = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)
    updated_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, nullable=False)
    passive_date = db.Column(db.DateTime, nullable=True)

    def __init__(self, program_name, program_code):
        self.program_name = program_name
        self.program_code = program_code
        self.created_at = datetime.now()
        self.is_active = True

    def to_dict(self):
        return {i.name: getattr(self, i.name) for i in self.__table__.columns if i.name == 'program_name' or i.name == 'program_code' or i.name == 'id'}


class Reports(db.Model):
    __tablename__  = 'reports'
    id             = db.Column(db.Integer,primary_key=True)
    report_email   = db.Column(db.String(120), nullable=True)
    report_user    = db.Column(db.String(120), nullable=True)
    report_route   = db.Column(db.String(500), nullable=True)
    report_message = db.Column(db.String(3000), nullable=True)
    report_date    = db.Column(db.DateTime, nullable=True)
    is_solved      = db.Column(db.Boolean, nullable=True)
    solve_time     = db.Column(db.DateTime, nullable=True)
    solve_by       = db.Column(db.String(120), nullable=True)
    
    def __init__(self, report_email, report_user, report_route, report_message):
        self.report_email = report_email
        self.report_user = report_user
        self.report_route = report_route
        self.report_message = report_message
        self.report_date = datetime.now()
        self.is_solved = False

class Search(db.Model):
    __tablename__ = 'search'
    id = db.Column(db.Integer, primary_key=True)
    filter_content = db.Column(db.String(100), nullable=False)
    filter_type = db.Column(db.String(100), nullable=False)
    filtered_by = db.Column(db.Integer, nullable=False)
    filter_date = db.Column(db.DateTime, nullable=False)

    def __init__(self, filter_content, filter_type, filtered_by, filter_date):
        self.filter_content = filter_content
        self.filter_type = filter_type
        self.filtered_by = filtered_by
        self.filter_date = filter_date

