#i want blog page be like this user can enter title, in the body he/she can upload any image then can add text  after that..if title and no image then add body like text;
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
from wtforms import StringField,BooleanField,EmailField,PasswordField,SubmitField,TextAreaField,FileField
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
#only allowed files can be uploaded
ALLOWED_EXTENSIONS={'png','jpeg','jpg'}
#get the folder to save uploaded files into
app.config['UPLOAD_FOLDER']=os.getenv('UPLOAD_FOLDER')
# print('Folder path: ',app.config['UPLOAD_FOLDER'])
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
    #get posts
    posts=Post.query.filter_by(user_id=current_user.id).all()
    # print("Posts: ",posts)
    # posts=Post.query.filter_by(user_id=current_user.id).all()
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
    return User.query.get(user_id)
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
    posts=Post.query.all()
    # print("Uploads: ",uploads)
    return render_template('posts.html',posts=posts)
#post route
@app.route('/create_post',methods=['POST','GET'])
@login_required
def create_post():
    #create instance of post form
    post=PostForm()
    if post.validate_on_submit():
        title=post.title.data.strip()
        content=post.content.data.strip()
        if not title and not content:
          post.title.errors.append("Title cannot be empty")
          post.content.errors.append("Content cannot be empty")
          return render_template("create_post.html", post=post)
        if title and not content:
          post.content.errors.append("Content is required when title is provided")
          return render_template("create_post.html", post=post)
        if content and not title:
          post.title.errors.append("Title is required when content is provided")
          return render_template("create_post.html", post=post)
        
        #save first post,  image is optional
        new_post=Post(
            title=title,
            content=content,
            user_id=current_user.id

        )
        #add title and content to the database
        db.session.add(new_post)
        #save changes
        db.session.commit()
        #check if there is image uploaded
        if post.image.data:
            #get the filename
            filename=secure_filename(post.image.data.filename)
            #check if folder does not exist
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                # print('Folder does not exist: ',app.config['UPLOAD_FOLDER'])
                #create folder
                os.makedirs(app.config['UPLOAD_FOLDER'])
            #create image path
            image_path=os.path.join(app.config['UPLOAD_FOLDER'],filename)
            # print(f"Image path:{image_path}")
            #save image path
            post.image.data.save(image_path)
            #save to the database
            #create instance of image
            post_image=PostImage(
                    #filename
                    filename=filename,
                    post_id=new_post.id
                )
                #save changes in the database
            db.session.add(post_image)
            #commit changes
            db.session.commit()
        # flash('Post created successfully','success')
        return redirect(url_for('display_posts'))
        # return render_template('create_post.html',post=post)
    return render_template('create_post.html',post=post)
    
#display images
@app.route('/uploads/<filename>')
def show_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

#serve images for download
@app.route('/post/<name>',methods=['POST','GET'])

def download_file(name):
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        name,
        as_attachment=True,
        #download name same as filename
        download_name=name
        )

#edit post
@app.route('/edit/<int:post_id>',methods=['POST','GET'])
@login_required
def edit_post(post_id):
    #get the post to delete
    post=Post.query.get_or_404(post_id)
    # print("Posts: ",post)
    # print("Posts image: ",post.images)
    if post.user_id!=current_user.id:
        flash('You are not allowed to edit this post','danger')
        #redirect to dashboard
        return redirect(url_for('dashboard'))
    #if valid
    #get the post form
    form=PostForm()
    #check if form is validated
    if form.validate_on_submit():
        #get the title
        post.title=form.title.data
        #get the content
        post.content=form.content.data
        #save changes
        # db.session.commit()       
        #handle image update
        if form.image.data:
            filename=secure_filename(form.image.data.filename)
            # print("Filename: ",filename)
            #ensure folder exists
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])
            #get image path
            image_path=os.path.join(app.config['UPLOAD_FOLDER'],filename)
            # print("File image edit path: ",image_path)
            
            #check if post has image
            if post.images:
                old_image=post.images[0]
                # print("Image path: ",post.images[0])
                #get old path
                old_path=os.path.join(app.config['UPLOAD_FOLDER'],old_image.filename)
                # print("Old path: ",old_path)
                #delete old path
                if os.path.exists(old_path):
                    #remove it
                    os.remove(old_path)
                #update filename in the database
                old_image.filename=filename
            else:
             new_image=PostImage(filename=filename,post_id=post.id)
             db.session.add(new_image)
            #save path
            form.image.data.save(image_path)
        #save changes
        db.session.commit()
        flash('Post updated successfully','success')
        return redirect(url_for('dashboard'))
     #prefill the form
    if request.method=='GET':
        form.title.data=post.title
        form.content.data=post.content    
    
    return render_template('edit_post.html',post=post,form=form)

#delete post
@app.route('/delete/<int:post_id>',methods=['POST','GET'])
@login_required
def delete_post(post_id):
    #get the post
    post=Post.query.get_or_404(post_id)
    if post.user_id!=current_user.id:
        flash("You cannot delete this post","danger")
        return redirect(url_for('dashboard'))
    #if authorized to delete
    #delete the post
    db.session.delete(post)
    #save changes to the database
    db.session.commit()
    flash("Post delete successfully","success")
    return redirect(url_for('dashboard'))

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


#form for creating post
class PostForm(FlaskForm):
    title=StringField('Title')
    image=FileField('Image(optional)',validators=[FileAllowed(ALLOWED_EXTENSIONS,message='Only images are allowed')])
    content=TextAreaField('Content')
    submit=SubmitField('Create post')


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
#create a database model for post table
class Post(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    #post title
    title=db.Column(db.String(36))
    #content
    content=db.Column(db.Text)
    #link post to a user
    user_id=db.Column(db.Integer,db.ForeignKey('user.id'))
    #date created
    created_at=db.Column(db.DateTime,default=datetime.utcnow)
    #add image
    images=db.relationship('PostImage',backref='post',lazy=True)
#create database table for image uploaded
class PostImage(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    #filename for image
    filename=db.Column(db.String(36))
    #link image to the post table
    post_id=db.Column(db.ForeignKey('post.id'))
if __name__=='__main__':
    with app.app_context():
      db.create_all()
    #   db.drop_all()

    app.run(debug=True)