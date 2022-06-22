from models import db
try:
    db.drop_all()
    print('Dropped all tables.')
except:
    pass
db.create_all()
print('Created all tables.')