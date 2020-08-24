from flask import Flask, request, render_template, redirect, flash, url_for
from flask_sqlalchemy import SQLAlchemy
import hashlib, binascii
from itsdangerous import URLSafeTimedSerializer
import yagmail
import random
import datetime

SECRET_KEY = '\xfd{H\xe5<\x95\xf9\xe3\x96.5\xd1\x01O<!\xd5\xa2\xa0\x9fR"\xa1\xa8'
SECURITY_PASSWORD_SALT = '\xfd{H\xe5<\x95\xf9\xe3\x96.5\xd1\x01O<!\xd5\xa2\xa0\x9fR"\xa1\xa8'
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///codes.db'


user = 'carofuturo.email@gmail.com'
app_password = 'barddlttmxjuserq'


app.config['SECRET_KEY'] = SECRET_KEY
app.config['SECURITY_PASSWORD_SALT'] = SECURITY_PASSWORD_SALT
db = SQLAlchemy(app)

# Commands for db
# To add a table:
# code = Codes(qrurl='the/url', user='the/user')
# db.session.add(code)
# db.session.commit()

# Query options:
# Codes.query.all()
# Change the word all with others if you need something in particular (ex. first())

# Codes.query.get_or_404(id)
# Codes.query.filter(Codes.[Something you want to filter. ex. user] == 'the user you want to check').all()

class Codes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    qrurl = db.Column(db.String(100), nullable=False)
    user = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return 'Id: ' + str(self.id) 

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.Text, nullable=False)
    user = db.Column(db.String(100), nullable=False)
    password = db.Column(db.Text, nullable=False)
    email_confirmation_sent_on = db.Column(db.DateTime, nullable=True)
    email_confirmed = db.Column(db.Boolean, nullable=True, default=False)
    email_confirmed_on = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return '\nId: ' + str(self.id) + '\nEmail: ' + str(self.email) + '\nUser: ' + str(self.user) + '\nPassword: ' + str(self.password)

ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
 
def generate_code():
    chars=[]
    for _ in range(6):
        chars.append(random.choice(ALPHABET))
    return "".join(chars)

salt = 'Jhonny Jhonny'
"""
token = generate_code()
content = 'X'

"""


@app.route('/create_qr')
def create_qr():
    """
        url = pyqrcode.create('johhnenenenen')
        url.png('myqr.png', scale = 6) 
    """
    return render_template('create_qr.html')

def send_email(email, content):
    with yagmail.SMTP(user, app_password) as yag:
        yag.send(email, 'Email di conferma account simplyorder', content)
        print('Sent email successfully')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user_email = request.form['email']
        user_username = request.form['username']
        user_password = request.form['password']
        if len(user_password) < 10:
            flash('The password must be more than 10 characters', 'warning')
            return redirect('/register')
        else:
            email_hash = hashlib.pbkdf2_hmac('sha256', bytes(user_email, 'utf-8') , bytes(salt, 'utf-8'), 10000)
            username_hash = hashlib.pbkdf2_hmac('sha256', bytes(user_username, 'utf-8') , bytes(salt, 'utf-8'), 10000)
            password_hash = hashlib.pbkdf2_hmac('sha256', bytes(user_password, 'utf-8') , bytes(salt, 'utf-8'), 10000)
            iduser = Users.query.filter(Users.user == username_hash).all()
            if len(iduser) >= 1:
                flash('The username is alredy taken. Try again', 'warning')

                return redirect('/register')
            else:
                new_user = Users(email=email_hash, user=username_hash, password=password_hash)
                db.session.add(new_user)
                db.session.commit()
                subject = "Please confirm your email"
                send_email(user_email, confirm_url)
                flash('Sent email')
                return redirect('/login')
    else:
        return render_template('register.html')

    return render_template('register.html')

@app.route('/confirm_email/<token>')
def confirm_email(token):
    pass


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_username = request.form['username']
        user_password = request.form['password']
        username_hash = hashlib.pbkdf2_hmac('sha256', bytes(user_username, 'utf-8') , bytes(salt, 'utf-8'), 10000)
        password_hash = hashlib.pbkdf2_hmac('sha256', bytes(user_password, 'utf-8') , bytes(salt, 'utf-8'), 10000)
        iduser = Users.query.filter(Users.user == username_hash).all()
        if len(iduser) >= 1:
            print(iduser)
            flash('You in my man', 'success')
        else:
            flash('Nope lmao', 'warning')

        #db.session.add(new_user)
        #db.session.commit()
        return redirect('/login')
    else:
        return render_template('login.html')
    return render_template('login.html')

@app.route('/')
def index():

    return render_template("index.html")


if __name__ == '__main__':
    app.run()
