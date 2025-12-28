from flask import Flask,render_template,url_for,redirect,flash,request,send_from_directory
from flask_login import login_manager,login_required,LoginManager,logout_user,UserMixin,current_user,login_user
#import register,login forms
# from forms import RegisterForm,LoginForm,User
from dotenv import load_dotenv
#import csrf protect
from flask_wtf import CSRFProtect
#import file features
from flask_wtf.file  import FileAllowed,FileField,FileRequired
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
#import form fields 
from wtforms import StringField,BooleanField,EmailField,PasswordField,SubmitField,TextAreaField,FileField,MultipleFileField
#import validators for form input
from wtforms.validators import InputRequired,EqualTo,Email,Length,ValidationError
from flask_wtf import FlaskForm
#prevent redirect attacks
from urllib.parse import urlparse,urljoin
#secure filename
from werkzeug.utils import secure_filename
#import datetime
from datetime import datetime
#import regex
import re
#import os
import os
#use hashlib to hash passwords and emails
import hashlib
#use json
from flask import jsonify
#eager load images
from sqlalchemy.orm import joinedload
#uuid postgresql
from sqlalchemy.dialects.postgresql import UUID
#user uuid for user id
import uuid 
#use supabase client
from supabase import create_client
#use flask migrate for database schema change
from flask_migrate import Migrate
load_dotenv()
#initialize app with flask
app=Flask(__name__)
SUPABASE_URL=os.getenv("SUPABASE_URL")
SUPABASE_KEY=os.getenv("SUPABASE_KEY")
#initialize app with supabase
supabase=create_client(SUPABASE_URL,SUPABASE_KEY)
#use secret key
app.config['SECRET_KEY']=os.getenv('SECRET_KEY')
#initialize app with csrf protect
csrf=CSRFProtect()
csrf.init_app(app)
#initialize app with bcrypt for hashing password
bcrypt=Bcrypt(app)
ALLOWED_EXTENSIONS={'png','jpeg','jpg'}
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#initializse app with database
db=SQLAlchemy(app)
#initialize flask migrate
migrate=Migrate(app,db)
login_manager=LoginManager()
login_manager.init_app(app)
#always redirect to login page
#if user is not logged in
login_manager.login_view='login'
login_manager.login_message_category='info'
#extract file path from url 
def extract_filename_from_url(url:str) -> str:
    return url.split("/")[-1]
#handle register route
@app.route('/register',methods=['POST','GET'])
def register():
    form=RegisterForm()
    if form.validate_on_submit():
        #hash user password
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
        login_user(existing_user, remember=form.remember_me.data)
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
#dashboard
@app.route('/dashboard',methods=['POST','GET'])
@login_required
def dashboard():
    #get posts
    posts=Post.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html',posts=posts)
#home page
@app.route('/home',methods=['POST','GET'])
def home():
    return render_template('home.html')
#handle prevent redirect attack
def is_safe_url(target):
    ref_url=urlparse(request.host_url)
    test_url=urlparse(urljoin(request.host_url,target))
    return(test_url.scheme in ('http','https') and ref_url.netloc==test_url.netloc)

#load user from the database
@login_manager.user_loader
def load_user(user_id):
    #fetch current user 
    return db.session.get(User,user_id)
#logout user
@app.route('/logout',methods=['POST','GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('display_posts'))
#uploads
@app.route('/')
@app.route('/posts')
def display_posts():
    #get uploads
    posts=(
        Post.query
        .order_by(Post.created_at.desc())
        .all()
    )
    return render_template('posts.html',posts=posts)
@app.route('/create_post', methods=['POST', 'GET'])
@login_required
def create_post():
    form = PostForm()
    if form.validate_on_submit():
          title = form.title.data.strip() if form.title.data else ""
          content = form.content.data.strip() if form.content.data else ""
          # Clear previous errors to avoid duplicates
          form.title.errors = []
          form.content.errors = []
          # Add errors only once per field
          if not title:
            form.title.errors.append("Title is required")
          if not content:
            form.content.errors.append("Content is required")
           # If there are errors, render the form
          if form.errors:
           return render_template("create_post.html", post=form, submit_label='Create post')
          # Create post
          new_post = Post(title=title, content=content, user_id=current_user.id)
          db.session.add(new_post)
          db.session.commit()  # commit to get post.id
          # flash("Post created successfully.", "success")
          return redirect(url_for('display_posts'))
    return render_template("create_post.html", post=form, submit_label='Create post')

@app.route('/edit/<string:post_id>', methods=['POST', 'GET'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id != current_user.id:
        flash("You are not allowed to edit this post.", "danger")
        return redirect(url_for('dashboard'))
    form = PostForm()
    if form.validate_on_submit():
        updated = False
        # Update title/content
        if form.title.data.strip() != (post.title or ""):
            post.title = form.title.data.strip()
            updated = True
        if form.content.data.strip() != (post.content or ""):
            post.content = form.content.data.strip()
            updated = True
        if updated:
            db.session.commit()
            return redirect(url_for('display_posts'))

    # Pre fill form on GET
    if request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content

    return render_template("edit_post.html", post=post, form=form, submit_label='Update post')

#delete post
@app.route('/delete/<string:post_id>',methods=['POST'])
@login_required
def delete_post(post_id):
    #get the post
    post=Post.query.get_or_404(post_id)
    if post.user_id!=current_user.id:
        return redirect(url_for('dashboard'))
    db.session.delete(post)
    #save changes to the database
    db.session.commit()
    return redirect(url_for('dashboard'))
#change password
@app.route('/change_password',methods=['POST','GET'])
@login_required
def change_password():
    form=ChangePasswordForm()
    user=User.query.get(current_user.id)
    user_password=user.password
    if not user:
      print("User not found")
    #get current user password
    if not user_password:
      print("No password set for this account")
    if form.validate_on_submit():
      #check if passwords match
      if not bcrypt.check_password_hash(user.password,form.current_password.data):
       form.current_password.errors.append('Current password is incorrect')
       return render_template('change_password.html',form=form)
      new_password_hash=bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
      #save changes to the database
      user.password=new_password_hash
      db.session.commit()
      flash('Password changed successfully','success')
      return redirect(url_for('login'))
    return render_template('change_password.html',form=form)

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
    def validate_password(self, new_password):
     pwd = new_password.data
     if len(pwd) < 8:
        raise ValidationError('Password must be at least 8 characters.')
     if not re.match(r'^[A-Za-z0-9_]+$', pwd):
        raise ValidationError('Password can only contain letters, numbers, and underscores.')
     if not (re.search(r'[A-Za-z]', pwd) and re.search(r'[\d_]', pwd)):
        raise ValidationError('Password must contain at least one letter and one number or underscore.')

#change password form
class ChangePasswordForm(FlaskForm):
    current_password=PasswordField('Current password',validators=[InputRequired()])
    new_password=PasswordField('New password',validators=[InputRequired()])
    confirm_new_password=PasswordField('Confirm new password',validators=[InputRequired(),EqualTo('new_password')])
    submit=SubmitField('Change Password')
    #validate password
    def validate_password(self, new_password):
     pwd = new_password.data
     if len(pwd) < 8:
        raise ValidationError('Password must be at least 8 characters.')
     if not re.match(r'^[A-Za-z0-9_]+$', pwd):
        raise ValidationError('Password can only contain letters, numbers, and underscores.')
     if not (re.search(r'[A-Za-z]', pwd) and re.search(r'[\d_]', pwd)):
        raise ValidationError('Password must contain at least one letter and one number or underscore.')



class PostForm(FlaskForm):
    title = StringField('Title')
    content = TextAreaField('Content')
    submit = SubmitField('Submit')

#login form
class LoginForm(FlaskForm):
    username=StringField('Username',validators=[InputRequired()])
    password=PasswordField('Password',validators=[InputRequired(),Length(min=8)])
    remember_me=BooleanField('Remember me')
    submit=SubmitField('Login')

#create user model
class User(db.Model,UserMixin):
    __tablename__ = 'users'
    id=db.Column(UUID(as_uuid=True),primary_key=True,default=uuid.uuid4)
    username=db.Column(db.String(36),nullable=False,unique=True,index=True)
    email=db.Column(db.String(70),nullable=False,unique=True,index=True)
    password=db.Column(db.String(255),nullable=False)
#create a database model for post table
class Post(db.Model):
    __tablename__='posts'
    id=db.Column(UUID(as_uuid=True),primary_key=True,default=uuid.uuid4)    #post title
    title=db.Column(db.String(36),nullable=True,index=True)
    #content
    content=db.Column(db.Text)
    #link post to a user
    user_id=db.Column(UUID(as_uuid=True),db.ForeignKey('users.id'),nullable=False)
    #date created
    created_at=db.Column(db.DateTime,default=datetime.utcnow)
if __name__=='__main__':
    app.run(debug=True)