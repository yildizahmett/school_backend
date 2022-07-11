# to be able to run update_db.py successfully, read the comment after the imports at models.py
from models import db
try:
    db.drop_all()
    print('Dropped all tables.')
except:
    pass
db.create_all()
print('Created all tables.')