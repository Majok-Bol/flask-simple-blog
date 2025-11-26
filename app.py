
from flask import Flask,render_template,url_for,redirect,flash
from flask_login import login_manager,login_required,LoginManager,logout_user,UserMixin,current_user,login_user
#import register,login forms
from forms import RegisterForm,LoginForm
from dotenv import load_dotenv
#import csrf protet
from flask_wtf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
import os
#initialize app with flask
app=Flask(__name__)
#initialize app with csrf protect
csrf=CSRFProtect()
csrf.init_app(app)

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
        #add user to database
        user=User(username=form.username.data,email=form.email.data,password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully','success')
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
        if existing_user is None:
            #if user does not exist
            #try login again
           return render_template('login.html',form=form)
        #else login user
        login_user(existing_user)
        flash('login successful','success')
        #redirect to the dashboard
        return redirect(url_for('dashboard'))
    return render_template('login.html',form=form)

@app.route('/dashboard',methods=['POST','GET'])
@login_required
def dashboard():
    msg='Welcome to your dashboard'
    return render_template('dashboard.html',msg=msg)
#load user from the database
@login_manager.user_loader
def load_user(user_id):
    #fetch current user 
    return db.session.get(User,user_id)
#create user model
class User(db.Model,UserMixin):
    id=db.Column(db.String(36),primary_key=True)
    username=db.Column(db.String(36),nullable=False)
    email=db.Column(db.String(50),nullable=False)
    password=db.Column(db.String(255),nullable=False)

if __name__=='__main__':
    with app.app_context():
      db.create_all()
        # db.drop_all()
    app.run(debug=True)