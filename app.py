from flask import Flask, render_template, redirect, url_for, jsonify, request, make_response, Response
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFError
from wtforms import StringField, PasswordField
from models import User, Session, LoginLog
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from collections import defaultdict
import time
import logging
import csv
from io import StringIO

# 登录失败跟踪结构：失败次数 + 上次失败时间
login_attempts = defaultdict(lambda: {'fail_count': 0, 'last_fail_time': None})
LOCKOUT_TIME = 300  # 锁定5分钟
MAX_ATTEMPTS = 5

# 日志记录配置
logging.basicConfig(filename='login.log', level=logging.INFO,
                    format='%(asctime)s - %(message)s')

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

class ProfileForm(FlaskForm):
    username = StringField('Username')

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
        username = form.username.data.strip()
        password_input = form.password.data
        session = Session()

        attempt = login_attempts[username]
        if attempt['fail_count'] >= MAX_ATTEMPTS:
            if time.time() - attempt['last_fail_time'] < LOCKOUT_TIME:
                session.close()
                logging.warning(f"{username} - ACCOUNT LOCKED - IP: {request.remote_addr}")
                return 'Account temporarily locked due to too many failed attempts', 403
            else:
                login_attempts[username] = {'fail_count': 0, 'last_fail_time': None}

        user = session.query(User).filter_by(username=username).first()

        if user and bcrypt.checkpw(password_input.encode('utf-8'), user.password_hash.encode('utf-8')):
            login_attempts[username] = {'fail_count': 0, 'last_fail_time': None}
            token = jwt.encode(
                {'username': user.username, 'role': user.role, 'exp': datetime.now(timezone.utc) + timedelta(hours=1)},
                JWT_SECRET, algorithm='HS256')

            log = LoginLog(username=username, ip=request.remote_addr, success=True)
            session.add(log)

            user_role = user.role
            session.commit()
            session.close()

            logging.info(f"{username} - LOGIN SUCCESS - IP: {request.remote_addr}")

            response = make_response(redirect(url_for('admin_panel') if user_role == 'admin' else url_for('profile')))
            response.set_cookie('jwt_token', token, httponly=True)
            return response
        else:
            attempt['fail_count'] += 1
            attempt['last_fail_time'] = time.time()
            log = LoginLog(username=username, ip=request.remote_addr, success=False)
            session.add(log)
            session.commit()
            session.close()
            logging.warning(f"{username} - LOGIN FAILED - IP: {request.remote_addr}")
            return 'Invalid credentials', 401
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('login')))
    response.set_cookie('jwt_token', '', expires=0)
    return response

@app.route('/admin')
def admin_panel():
    token = request.cookies.get('jwt_token')
    if not token:
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        if data['role'] != 'admin':
            return jsonify({'error': 'Forbidden: Admins only'}), 403
        session = Session()
        users = session.query(User).all()
        session.close()
        return render_template('admin.html', users=users)
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/login_logs')
def login_logs():
    token = request.cookies.get('jwt_token')
    if not token:
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        if data['role'] != 'admin':
            return jsonify({'error': 'Forbidden'}), 403
        session = Session()
        logs = session.query(LoginLog).order_by(LoginLog.timestamp.desc()).all()
        session.close()
        return render_template('login_logs.html', logs=logs)
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/export_logs')
def export_logs():
    token = request.cookies.get('jwt_token')
    if not token:
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        if data['role'] != 'admin':
            return jsonify({'error': 'Forbidden'}), 403

        session = Session()
        logs = session.query(LoginLog).order_by(LoginLog.timestamp.desc()).all()
        session.close()

        si = StringIO()
        writer = csv.writer(si)
        writer.writerow(['Username', 'IP', 'Success', 'Timestamp'])

        for log in logs:
            writer.writerow([log.username, log.ip, str(log.success), log.timestamp])

        output = make_response(si.getvalue())
        output.headers['Content-Disposition'] = 'attachment; filename=login_logs.csv'
        output.headers['Content-type'] = 'text/csv'
        return output
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/login_stats')
def login_stats():
    token = request.cookies.get('jwt_token')
    if not token:
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        if data['role'] != 'admin':
            return jsonify({'error': 'Forbidden'}), 403

        session = Session()
        logs = session.query(LoginLog).all()
        session.close()

        stats = {}
        for log in logs:
            day = log.timestamp.strftime('%Y-%m-%d')
            if day not in stats:
                stats[day] = {'success': 0, 'fail': 0}
            if log.success:
                stats[day]['success'] += 1
            else:
                stats[day]['fail'] += 1

        result = {
            'dates': sorted(stats.keys()),
            'success_counts': [stats[d]['success'] for d in sorted(stats.keys())],
            'fail_counts': [stats[d]['fail'] for d in sorted(stats.keys())]
        }
        return jsonify(result)
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    token = request.cookies.get('jwt_token')
    if not token:
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        session = Session()
        user = session.query(User).filter_by(username=data['username']).first()
        if not user:
            session.close()
            return jsonify({'error': 'User not found'}), 404
        form = ProfileForm()
        if request.method == 'POST' and 'csrf_token' not in request.form:
            return jsonify({'error': 'CSRF token missing'}), 403
        if form.validate_on_submit():
            user.username = form.username.data
            session.commit()
            session.close()
            return redirect(url_for('profile'))
        session.close()
        form.username.data = user.username
        return render_template('profile.html', user=user, form=form)
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401
@app.route('/api/status')
def api_status():
    token = request.cookies.get('jwt_token')
    if not token:
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return jsonify({
            'status': 'ok',
            'user': data['username'],
            'role': data['role'],
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/')
def home():
    return 'Secure User System'

if __name__ == '__main__':
    app.run(debug=True)
