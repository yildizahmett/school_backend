from flask import Flask
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta

TOKEN_EXPIRE_TIME = 2 # HOURS
app = Flask(__name__)
app.config.from_pyfile('config.cfg')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=TOKEN_EXPIRE_TIME)

bcrypt = Bcrypt(app)
jwt = JWTManager(app)
db = SQLAlchemy(app)
CORS(app)