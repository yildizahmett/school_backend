from datetime import datetime
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy


TOKEN_EXPIRE_TIME = 2 # HOURS
app = Flask(__name__)
app.config.from_pyfile('config.cfg')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=TOKEN_EXPIRE_TIME)

bcrypt = Bcrypt(app)
jwt = JWTManager(app)
db = SQLAlchemy(app)
CORS(app)

class Students(db.Model):
    __table_name__ = 'students'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    surname = db.Column(db.String(120), nullable=False)
    linkedin = db.Column(db.String(240), nullable=True)
    github = db.Column(db.String(240), nullable=True)
    medium = db.Column(db.String(240), nullable=True)
    program_name = db.Column(db.String(120), nullable=True)
    comp_skils = db.Column(db.ARRAY(db.String(120)), nullable=True)
    hobbies = db.Column(db.ARRAY(db.String(120)), nullable=True)
    birth_date = db.Column(db.DateTime, nullable=True)
    english_level = db.Column(db.String(120), nullable=True)
    reference = db.Column(db.String(120), nullable=True)
    starting_date = db.Column(db.DateTime, nullable=True)
    job_title = db.Column(db.String(120), nullable=True)
    workplace_type = db.Column(db.String(120), nullable=True)
    city = db.Column(db.String(120), nullable=True)
    country = db.Column(db.String(120), nullable=True)
    salary_min = db.Column(db.Integer, nullable=True)
    salary_max = db.Column(db.Integer, nullable=True)
    is_temp = db.Column(db.Boolean, nullable=False)
    date = db.Column(db.DateTime, nullable=False)

    favourites = db.relationship('Favourites', backref='students_ref', lazy=True)

    def __init__(self, email, password, name, surname):
        self.email = email
        self.password = password
        self.name = name
        self.surname = surname
        self.is_temp = True
        self.date = datetime.now()

    def to_dict(self):
        return {i.name: getattr(self, i.name) for i in self.__table__.columns if i.name != 'password'}

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

class Companies(db.Model):
    __tablename__ = 'companies'
    id=db.Column(db.Integer,primary_key=True)
    company_name = db.Column(db.String(100), nullable=False, unique=True)
    special_id = db.Column(db.String(20), unique=True)
    company_users = db.Column(db.ARRAY(db.String(100)))
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