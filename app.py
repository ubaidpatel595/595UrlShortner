from flask import Flask,render_template,request,session,flash,jsonify,Response,redirect
import pymongo
import random
from flask_bcrypt import Bcrypt
import jwt
from datetime import datetime,timedelta
from flask_mail import Mail,Message
import threading

app = Flask("urlShortner")
app.secret_key = "ubaidqwrtyu"

# Configuring mail servicve
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_USERNAME'] = 'ubaidpatel595@gmail.com'
app.config['MAIL_PASSWORD'] = 'dzavvnlewlytlute'
app.config['MAIL_DEFAULT_SENDER'] = 'ubaidpatel595@gmail.com'
mail = Mail(app)

#Password Encoder To secure passwords
bcrypt = Bcrypt(app)

#Mongo Db Comfiguration
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client['urlshort']
collect = db['urls']
users = db['users']

#Generates Unique Endpoint for shorted Url
def uniqueEnd(len):
    str = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm12234567890"
    rand = random.choices(str,k=len)
    return "".join(rand)

#Generates JWT for password reset link
def generateJwt(userid,time):
        paload = {
            'exp':datetime.utcnow()+timedelta(minutes=time),
            'iat':datetime.utcnow(),
            'sub':userid
          }
        token = jwt.encode(
        paload,
        app.config['SECRET_KEY'],
        algorithm='HS256'
        )
        return token

#Send Mails To Users
def SendEmail(email,token):
    with app.app_context():
        msg = Message("Password Reset 595_URL_SHORTNER",recipients=[email],sender="ubaidpatel595@gmail.com")
        msg.html = '<h4>Password Reset Link Valid for 10 Minutes </h4><a href='+token+'>Click Here To Reset Password</a>'
        try:
           mail.send(msg)
           print("sent")
        except RuntimeError as e:
            print(e.__context__)


@app.route("/",methods=["GET","POST"])
def home():
  urls =[]
  if request.method == 'POST':
    url = request.form['url']
    alvail = False
    endpoint = ''
    while alvail == False:
        endpoint= uniqueEnd(6)
        cursor =  collect.find_one({"endpoint":endpoint})
        if cursor == None:
            if session['loggedIn'] == True:
                collect.insert_one({"url":url,"endpoint":endpoint,"user":session['userId']})
            else:
             collect.insert_one({"url":url,"endpoint":endpoint})
            alvail = True
    url=request.host_url+endpoint
    if session['loggedIn'] ==True:
        return redirect("/")
    return render_template("result.html",url=url)
  else:
    if session['loggedIn'] == True:
        cursor = collect.find({"user":session['userId']})
        for doc in cursor:
            urls.append(doc)
    return render_template('index.html',prevurls=urls,session=session)
@app.route("/<endpoint>",)
def redir(endpoint):
    data  = collect.find_one({"endpoint":endpoint})
    return redirect(data['url'])


@app.route("/login",methods=["GET","POST"])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        cursor = users.find_one({"email":email})
        if cursor != None:
            passh = cursor['password']
            if bcrypt.check_password_hash(passh,password):
                session["userId"] = cursor['email']
                session['loggedIn'] = True
                flash('Login Success')
                return render_template("login.html",logged=True)
            else:
                flash('Incorrect Password')
        else:
            flash('User Not Found Please Create Account')
    return render_template("login.html",logged=False)

@app.route("/signup",methods=["GET","POST"])
def register():
    if request.method == "POST":
        password = request.form['password']
        mobile = request.form['mobile']
        email = request.form['email']
        cursor = users.find_one({"email":email})
        passh = bcrypt.generate_password_hash(password).decode('utf-8')
        cursor = users.find_one({"email":email})
        if cursor == None:
            users.insert_one({"email":email,"mobile":mobile,"password":passh})
            return "Account created successfull"
        else:
            return "User already exist"
    return render_template("register.html")

@app.route("/changepassword",methods=["GET","POST"])
def changepass():
    if session['loggedIn'] == False:
        return redirect("/")
    if request.method == 'POST':
        password = request.form['oldPassword']
        newpassword = request.form['newPassword']
        if session['loggedIn']:
            print("loggedin")
            user = session['userId']
            cursor =  users.find_one({"email":user})
            if bcrypt.check_password_hash(cursor['password'],password):
                newdat = cursor
                newpass = bcrypt.generate_password_hash(newpassword).decode('utf-8')
                result = users.update_one({"email":user},{"$set":{"password":newpass}})
                if result.modified_count == 1:
                    return "Password Change Success"
            else:
                return "Incorrect Old Password"
            return "logged in"+newpassword
        else:
            print("noit")
            return "Logout"
    else:
        return render_template("changepass.html")

@app.route("/forgotPassword",methods = ['GET','POST'])
def reset():
    if request.method == 'POST':
        email = request.form['email']
        cursor = users.find_one({"email":email})
        if cursor !=None:
            token =request.host_url+"ResetPassword/"+generateJwt(cursor['email'],10)
            threading.Thread(target=SendEmail,args=(email,token)).start()
            flash("Reset Link Sent To Registered Email")
        else:
            flash("User Not Found Please Register")
    return render_template("forgotPassword.html")

@app.route("/ResetPassword/<token>",methods=["GET","POST"])
def ResetPass(token):
    if request.method == 'POST':
        try:
            token = jwt.decode(token.encode(),app.secret_key,'HS256')
            print(token['sub'])
            password = request.form['password']
            email = token['sub']
            passh =  bcrypt.generate_password_hash(password=password).decode('utf-8')
            users.update_one({"email":email},{'$set':{"password":passh}})
            print(password)
            return "Password Change Success"
        except Exception as e:
            print(e.__class__)
            return "Link Expired"
    else:
        return render_template("resetPassword.html")
@app.route("/editLink/<endpoint>",methods=["GET","POST"])
def editlink(endpoint):
    if session['loggedIn'] == False:
        return redirect("/")
    logged =False
    if request.method == 'POST':
        link = request.form['link']
        collect.update_one({"endpoint":endpoint},{"$set":{"url":link}})
        flash("Link Edited Success")
        logged =True
        return  render_template("editLink.html",url=link,logged=logged)
    else:
        link = collect.find_one({"endpoint":endpoint})
    return render_template("editLink.html",url=link['url'],logged=logged)

@app.route("/Logout")
def Logout():
    session['userId']=None
    session['loggedIn'] = False
    flash("Succesfully Logged Out")
    return render_template("logout.html",logged = True)

@app.route("/delete/<endpoint>")
def delete(endpoint):
    res = collect.delete_one({"endpoint":endpoint})
    return redirect("/")
    
app.run()