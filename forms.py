from flask_wtf import FlaskForm
from wtforms import SubmitField, StringField, PasswordField
from wtforms.validators import InputRequired, Email
from custom_validators import check_password, check_email, check_login


class RegisterForm(FlaskForm):

    name = StringField(validators=[InputRequired()])
    last_name = StringField(validators=[InputRequired()])
    email = StringField(validators=[InputRequired(),Email(),check_email])
    password = PasswordField(validators=[InputRequired(),check_password])
    submit = SubmitField()



class LoginForm(FlaskForm):

    email = StringField(validators=[InputRequired(),Email()])
    password = PasswordField(validators=[InputRequired(),check_login])
    submit = SubmitField()


class NewPassword(FlaskForm):

    password = PasswordField(validators=[InputRequired(),check_password])
    submit = SubmitField()

