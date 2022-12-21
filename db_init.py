from main import db

def run_init():
    db.drop_all()
    db.create_all()

run_init()