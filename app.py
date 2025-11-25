from flask import Flask,render_template,url_for,redirect,flash
#initialize app with flask
app=Flask(__name__)
@app.route('/')
@app.route('/home',methods=['POST','GET'])
def home():
    return render_template('home.html')



if __name__=='__main__':
    app.run(debug=True)