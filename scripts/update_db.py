from util import db
try:
    db.drop_all()
except:
    pass
db.create_all()