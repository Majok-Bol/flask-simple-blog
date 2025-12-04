
from flask import Flask,render_template,url_for,redirect,flash,request
from flask_login import login_manager,login_required,LoginManager,logout_user,UserMixin,current_user,login_user
#import register,login forms
# from forms import RegisterForm,LoginForm,User
from dotenv import load_dotenv
#import csrf protect
from flask_wtf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
#import form fields 
from wtforms import StringField,BooleanField,EmailField,PasswordField,SubmitField,TextAreaField
#import validators for form input
from wtforms.validators import InputRequired,EqualTo,Email,Length,ValidationError
from flask_wtf import FlaskForm
#prevent redirect attacks
from urllib.parse import urlparse,urljoin
#import datetime
from datetime import datetime
#import regex
import re
#import os
import os
#initialize app with flask
app=Flask(__name__)
#initialize app with csrf protect
csrf=CSRFProtect()
csrf.init_app(app)
#initialize app with bcrypt for hashing password
bcrypt=Bcrypt(app)
#load env files
load_dotenv('.env')
#use secret key
app.config['SECRET_KEY']=os.getenv('SECRET_KEY')
#configure database url
app.config['SQLALCHEMY_DATABASE_URI']=os.getenv('DATABASE_URL')
#Dont track model changes
#if yes,app will be slow
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
#initializse app with database
db=SQLAlchemy(app)
#initialize login manager
#manage user sessions
login_manager=LoginManager()
login_manager.init_app(app)
#always redirect to login page
#if user is not logged in
login_manager.login_view='login'
login_manager.login_message_category='info'
#handle root url
@app.route('/')
@app.route('/home',methods=['POST','GET'])
def home():
    return render_template('home.html')

#handle register route
@app.route('/register',methods=['POST','GET'])
def register():
    form=RegisterForm()
    if form.validate_on_submit():
        #get user details
        #hash use password
        #decode as string
        hashed_password=bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        #add user to database
        user=User(username=form.username.data,email=form.email.data,password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully.Please login.','success')
        #redirect to login page
        return redirect(url_for('login',form=form))
    return render_template('register.html',form=form)

#handle login
@app.route('/login',methods=['POST','GET'])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        #get user from the database
        existing_user=User.query.filter_by(username=form.username.data).first()
        #if user not found
        #show error
        if existing_user is None:
            form.username.errors.append('Username not found.')
            return render_template('login.html',form=form)
        if not bcrypt.check_password_hash(existing_user.password,form.password.data):
            form.password.errors.append('Password is incorrect')
            return render_template('login.html',form=form)
        #login user
        #when username and password is correct
        login_user(existing_user)
        # flash('login successful','success')
        #check for redirect route
        next_page=request.args.get('next')
        if next_page and is_safe_url(next_page):
            #if safe redirect
            #go to next parameter
            #go to that page
            return redirect(next_page)
         #redirect to the dashboard
        return redirect(url_for('dashboard'))
    return render_template('login.html',form=form)

@app.route('/dashboard',methods=['POST','GET'])
@login_required
def dashboard():
    posts=Post.query.filter_by(user_id=current_user.id).all()
    # print('Posts: ',posts)
    msg='Welcome to your dashboard'
    return render_template('dashboard.html',posts=posts)
#load user from the database
@login_manager.user_loader
def load_user(user_id):
    #fetch current user 
    return User.query.get(user_id)
#logout user
@app.route('/logout',methods=['POST','GET'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out','warning')
    return redirect(url_for('login'))

#handle prevent redirect attack
def is_safe_url(target):
    ref_url=urlparse(request.host_url)
    test_url=urlparse(urljoin(request.host_url,target))
    return(test_url.scheme in ('http','https') and ref_url.netloc==test_url.netloc)
#route to handle text area input
@app.route('/post',methods=['POST','GET'])
@login_required
def post():
       #use instance of text area form 
    form=TextAreaForm()
    #get form data
    post=None
    if form.validate_on_submit():
        post=form.content.data
        # print("Content: ",post)
        flash('Your post has been created.','success')
        #save changes to the database
        new_post=Post(content=form.content.data,user_id=current_user.id)
        db.session.add(new_post)
        db.session.commit()
        #redirect to dashboard
        return redirect(url_for('dashboard'))

    return render_template('create_post.html',form=form)


#text area form
class TextAreaForm(FlaskForm):
    content=TextAreaField('Content',validators=[Length(min=10)])
    submit=SubmitField('Create post')

 
#registration form
class RegisterForm(FlaskForm):
    username=StringField('Username',validators=[InputRequired(),Length(min=4,max=50)])
    email=EmailField('Email address',validators=[InputRequired(),Email(),Length(max=50)])
    password=PasswordField('Password',validators=[InputRequired(),Length(min=8,max=255)])
    confirm_password=PasswordField('Confirm password',validators=[InputRequired(),Length(min=8,max=255),EqualTo('password',message='Passwords must match')])
    submit=SubmitField('Register')

    def validate_username(self,username):
        user=User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already in use.Please try another username')
        if " " in username.data:
            raise ValidationError('Username must be a single word without spaces')

    def validate_email(self,email):
        email=User.query.filter_by(email=email.data).first()
        if email:
            raise ValidationError('Email already in use.Please try another email address')
    def validate_password(self,password):
        pwd=password.data
        if len(pwd)<8:
            raise ValidationError('Password must be atleast 8 characters.')
        if not re.match(r'^[A-Za-z0-9_]+$',pwd):
            raise ValidationError('Password can only contain letters,numbers and underscores')
        has_letters=re.search(r'[A-Za-z]',pwd)
      
        has_numbers_or_underscores=re.search(r'[\d_]',pwd)

        if not (has_letters and has_numbers_or_underscores):
            raise ValidationError('Password must contain atleast 1 letter,number or underscore')


  


#login form
class LoginForm(FlaskForm):
    username=StringField('Username',validators=[InputRequired()])
    password=PasswordField('Password',validators=[InputRequired(),Length(min=8)])
    remember_me=BooleanField('Remember me')
    submit=SubmitField('Login')

#create user model
class User(db.Model,UserMixin):
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(36),nullable=False)
    email=db.Column(db.String(50),nullable=False)
    password=db.Column(db.String(255),nullable=False)
    #link user model with post model
    #one to many relationship
    #one user can create many posts
    posts=db.relationship('Post',lazy=True,backref='author')

class Post(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    content=db.Column(db.Text)
    #link post model with user model
    #match user post id with user id
    user_id=db.Column(db.Integer,db.ForeignKey('user.id'))
    date_created=db.Column(db.DateTime,default=datetime.utcnow)
if __name__=='__main__':
    with app.app_context():
    #   db.create_all()
      db.drop_all()

    app.run(debug=True)