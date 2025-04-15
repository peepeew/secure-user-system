from flask import Flask, render_template
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-123'  # 改成随机值

class LoginForm(FlaskForm):
    username = StringField('Username')
    password = PasswordField('Password')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        return 'Login OK'  # 占位，明天实现验证
    return render_template('login.html', form=form)

@app.route('/')
def home():
    return 'Secure User System'

if __name__ == '__main__':
    app.run(debug=True)