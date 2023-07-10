from app import db
from re import match

def is_valid_email(email):
    email_regex = r'^[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*(\.[a-z]+)$'
    return match(email_regex, email) is not None

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    salt = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)

    def __init__(self, username, password, salt, email):
        self.username = username
        self.password = password
        self.salt = salt
        if not is_valid_email(email):
            raise ValueError("Invalid email format")
        self.email = email
    def save(self):
        db.session.add(self)
        db.session.commit()
        

