from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash


db = SQLAlchemy()

class User(UserMixin,db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String,nullable=False, unique=True)
    name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    password = db.Column(db.String)
    date_added = db.Column(db.DateTime)
    todos = db.relationship('Todo', backref='user')

    def __init__(self,email,name,last_name,password,date_added):
        self.email = email
        self.name = name
        self.last_name = last_name
        self.password = generate_password_hash(password)
        self.date_added = date_added





class Todo(db.Model):
    __tablename__ = 'todo'

    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(100))
    added = db.Column(db.DateTime)
    user_id = db.Column(db.Integer,db.ForeignKey('user.id'))



