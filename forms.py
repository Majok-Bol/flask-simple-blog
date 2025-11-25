
#import form fields 
from wtforms import StringField,BooleanField,EmailField,PasswordField
#import validators for form input
from wtforms.validators import InputRequired,EqualTo,Email,Length
from flask_wtf import FlaskForm
#registration form
class RegisterForm(FlaskForm):
    username=StringField('Username',validators=[InputRequired(),Length(min=4,max=50)])
    email=EmailField('Email address',validators=[InputRequired(),Email(),Length(max=50)])
    password=PasswordField('Password',validators=[InputRequired(),Length(min=8,max=255)])
    confirm_password=PasswordField('Confirm password',validators=[InputRequired(),Length(min=8,max=255),EqualTo('password',message='Passwords must match')])

#login form
class LoginForm(FlaskForm):
    username=StringField('Username',validators=[InputRequired()])
    password=PasswordField('Password',validators=[InputRequired(),Length(min=8)])
