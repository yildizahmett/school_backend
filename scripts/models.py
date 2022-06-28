from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSON as pg_JSON
from datetime import datetime
from scripts.util import db
# to be able to run update_db.py successfully, remove 'scripts.'  from the line above then add it after you're done


class Temps(db.Model):
    __table_name__  = 'temps'
    id              = db.Column(db.Integer, primary_key=True)
    email           = db.Column(db.String(120), unique=True, nullable=False)
    password        = db.Column(db.String(255), nullable=False)
    name            = db.Column(db.String(120), nullable=False)
    surname         = db.Column(db.String(120), nullable=False)
    date            = db.Column(db.DateTime, nullable=False)

    def __init__(self, email, password, name, surname):
        self.email = email
        self.password = password
        self.name = name
        self.surname = surname
        self.date = datetime.now()


class Students(db.Model):
    __table_name__  = 'students'
    id              = db.Column(db.Integer, primary_key=True)
    email           = db.Column(db.String(120), unique=True, nullable=False)
    password        = db.Column(db.String(255), nullable=False)
    name            = db.Column(db.String(120), nullable=False)
    surname         = db.Column(db.String(120), nullable=False)
    phone           = db.Column(db.String(25), nullable=True) # the length may be shortened
    summary         = db.Column(db.String(255), nullable=True)
    linkedin        = db.Column(db.String(240), nullable=True)
    github          = db.Column(db.String(240), nullable=True)
    medium          = db.Column(db.String(240), nullable=True)
    program_name    = db.Column(db.String(120), nullable=True)
    comp_skills     = db.Column(db.ARRAY(db.String(120)), nullable=True)
    hobbies         = db.Column(db.ARRAY(db.String(120)), nullable=True)
    birth_date      = db.Column(db.DateTime, nullable=True)
    english_level   = db.Column(db.String(120), nullable=True) # this might be removed due to how languages are stored
    reference       = db.Column(db.String(120), nullable=True)
    starting_date   = db.Column(db.DateTime, nullable=True)
    job_title       = db.Column(db.String(120), nullable=True)
    educations      = db.Column(pg_JSON)
    experiences     = db.Column(pg_JSON)
    projects        = db.Column(pg_JSON)
    languages       = db.Column(pg_JSON)
    workplace_type  = db.Column(db.String(120), nullable=True)
    city            = db.Column(db.String(120), nullable=True)
    country         = db.Column(db.String(120), nullable=True)
    salary_min      = db.Column(db.Integer, nullable=True)
    salary_max      = db.Column(db.Integer, nullable=True)
    salary_currency = db.Column(db.String(10), nullable=True)
    profile_complete = db.Column(db.Boolean, nullable=False)
    date            = db.Column(db.DateTime, nullable=False)

    favourites      = db.relationship('Favourites', backref='students_ref', lazy=True)

    def __init__(self, email, password, name, surname):
        self.email = email
        self.password = password
        self.name = name
        self.surname = surname
        self.profile_complete = False
        self.date = datetime.now()

    def to_dict(self):
        return {i.name: getattr(self, i.name) for i in self.__table__.columns if i.name != 'password'}

class Companies(db.Model):
    __tablename__ = 'companies'
    id=db.Column(db.Integer,primary_key=True)
    company_name = db.Column(db.String(100), nullable=False, unique=True)
    special_id = db.Column(db.String(20), unique=True)
    company_users = db.Column(db.ARRAY(db.String(100)), nullable=True)
    date = db.Column(db.DateTime, nullable=False)

    employees = db.relationship('Employees', backref='companies_ref', lazy=True)
    favourites = db.relationship('Favourites', backref='companies_ref', lazy=True)

    def __init__(self, company_name, special_id, company_users):
        self.company_name = company_name
        self.special_id = special_id
        self.company_users = company_users
        self.date = datetime.now()

    def add_user(self, user):
        self.company_users.append(user)

    def to_dict(self):
        return {i.name: getattr(self, i.name) for i in self.__table__.columns}

class Employees(db.Model):
    __table_name__ = 'employees'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    surname = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    company = db.Column(db.ForeignKey('companies.special_id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False)

    favourites = db.relationship('Favourites', backref='employees_ref', lazy=True)

    def __init__(self, name, surname, email, password, company):
        self.name = name
        self.surname = surname
        self.email = email
        self.password = password
        self.company = company
        self.date = datetime.now()


class Favourites(db.Model):
    __tablename__ = 'favourites'
    id=db.Column(db.Integer,primary_key=True)
    student_id = db.Column(db.ForeignKey('students.id'), nullable=False)
    company_name = db.Column(db.ForeignKey('companies.company_name'), nullable=False)
    employee_email = db.Column(db.ForeignKey('employees.email'), nullable=False)
    date = db.Column(db.DateTime)

    def __init__(self, student_id, company_name, employee_email):
        self.student_id = student_id
        self.company_name = company_name
        self.employee_email = employee_email
        self.date = datetime.now()