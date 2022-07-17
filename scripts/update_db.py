import sys
import os
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from models import db

def reset_db():
    

    try:
        db.drop_all()
        print('Dropped all tables.')
    except:
        pass
    db.create_all()
    print('Created all tables.')

if __name__ == '__main__':
    reset_db()