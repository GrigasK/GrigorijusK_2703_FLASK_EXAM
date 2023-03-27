from flask_wtf import FlaskForm
from wtforms import SubmitField, BooleanField, StringField, PasswordField, FloatField
from wtforms.validators import DataRequired, ValidationError, EqualTo
import app


class RegisterForm(FlaskForm):
    name = StringField('Name', [DataRequired()])
    email = StringField('Email', [DataRequired()])
    password = PasswordField('Password', [DataRequired()])
    confirmed_password = PasswordField("Confirm password", [
        EqualTo('password', "Password must be matched")])
    submit = SubmitField('Regsiter')

    def check_name(self, name):
        user = app.User.query.filter_by(name=name.data).first()
        if user:
            raise ValidationError(
                'This name is already used by another user, please choose another name')

    def tikrinti_pasta(self, email):
        user = app.User.query.filter_by(
            email=email.data).first()
        if user:
            raise ValidationError(
                'This email address is already used by another user, please choose another email address.')


class LoginForm(FlaskForm):
    email = StringField('Email', [DataRequired()])
    password = PasswordField('Password', [DataRequired()])
    remember = BooleanField("Remember me")
    submit = SubmitField('Log in')


class GroupForm(FlaskForm):
    group_name = BooleanField('Group name')
    submit = SubmitField('Submit')
