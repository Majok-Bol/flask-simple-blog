
from flask import Flask,render_template,url_for,redirect,flash
#import register,login forms
from forms import RegisterForm,LoginForm
from dotenv import load_dotenv
import os
#initialize app with flask
app=Flask(__name__)
#load env files
load_dotenv('.env')
#use secret key
app.config['SECRET_KEY']=os.getenv('SECRET_KEY')
@app.route('/')
@app.route('/home',methods=['POST','GET'])
def home():
    return render_template('home.html')

#handle register route
@app.route('/register',methods=['POST','GET'])
def register():
    form=RegisterForm()
    if form.validate_on_submit():
        #redirect to login page
        return redirect(url_for('login',form=form))
    return render_template('register.html',form=form)

#handle login
@app.route('/login',methods=['POST','GET'])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        return redirect(url_for('dashboard'))
    return render_template('login.html',form=form)

@app.route('/dashboard',methods=['POST','GET'])
def dashboard():
    msg='Welcome to your dashboard'
    return render_template('dashboard.html',msg=msg)
if __name__=='__main__':
    app.run(debug=True)