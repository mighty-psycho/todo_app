from wtforms.validators import ValidationError
from models import User
from werkzeug.security import check_password_hash


def check_password(form, field):
    if len(field.data) < 8:
        raise ValidationError('Please check Your password')


def check_email(form,field):
    user_email = User.query.filter_by(email=field.data).first()
    if user_email:
        raise ValidationError('Email already exist, please choose another one or login')


def check_login(form,field):
    user = User.query.filter_by(email=form.email.data).first()
    if not user:
        raise ValidationError('You have entered an invalid username or password')
    elif not check_password_hash(user.password,field.data):
        raise ValidationError('You have entered an invalid username or password')