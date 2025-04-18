from flask import Flask, render_template, redirect, url_for, jsonify, request
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFError
from wtforms import StringField, PasswordField
from models import User, Session
import bcrypt
import jwt
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-123'
app.config['WTF_CSRF_ENABLED'] = True
JWT_SECRET = 'jwt-secret-456'

class RegisterForm(FlaskForm):
    username = StringField('Username')
    password = PasswordField('Password')

class LoginForm(FlaskForm):
    username = StringField('Username')
    password = PasswordField('Password')

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return jsonify({'error': 'CSRF token missing or invalid'}), 403

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == 'POST' and 'csrf_token' not in request.form:
        return jsonify({'error': 'CSRF token missing'}), 403
    if form.validate_on_submit():
        session = Session()
        existing_user = session.query(User).filter_by(username=form.username.data).first()
        if existing_user:
            session.close()
            return 'Username already exists', 400
        username = form.username.data
        password = form.password.data.encode('utf-8')
        hashed = bcrypt.hashpw(password, bcrypt.gensalt())
        user = User(username=username, password_hash=hashed.decode('utf-8'), role='user')
        session.add(user)
        session.commit()
        session.close()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST' and 'csrf_token' not in request.form:
        return jsonify({'error': 'CSRF token missing'}), 403
    if form.validate_on_submit():
        session = Session()
        user = session.query(User).filter_by(username=form.username.data).first()
        if user and bcrypt.checkpw(form.password.data.encode('utf-8'), user.password_hash.encode('utf-8')):
            token = jwt.encode(
                {'username': user.username, 'role': user.role, 'exp': datetime.utcnow() + timedelta(hours=1)},
                JWT_SECRET, algorithm='HS256')
            session.close()
            return jsonify({'token': token})
        session.close()
        return 'Invalid credentials', 401
    return render_template('login.html', form=form)

@app.route('/')
def home():
    return 'Secure User System'

if __name__ == '__main__':
    app.run(debug=True)