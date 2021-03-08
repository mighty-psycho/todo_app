from flask import Flask, redirect, render_template, url_for, request, flash
from flask_mail import Mail, Message
from forms import RegisterForm, LoginForm, NewPassword
from flask_migrate import Migrate
from models import db, User, Todo
from datetime import datetime, timedelta
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired


app = Flask(__name__)

app.config['SECRET_KEY'] = 'secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = "database"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(hours=1)
app.config.from_pyfile('config.cfg')

db.init_app(app)
Migrate(app,db)

login = LoginManager(app)

serializer = URLSafeTimedSerializer(app.secret_key)

mail = Mail(app)


@app.before_first_request
def create_all():
    db.create_all()

@login.user_loader
def load_user(id):
    return User.query.get(id)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login',methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        flash('You are already logged in')
        return redirect(url_for('todo'))

    log_form = LoginForm()
    if log_form.validate_on_submit():
        user = User.query.filter_by(email=log_form.email.data).first()
        if user:
            login_user(user,remember=True)
            return redirect(url_for('todo'))

    return render_template('login.html', log_form=log_form)


@app.route('/register',methods=['GET','POST'])
def register():
    if current_user.is_authenticated:
        flash('You are already registered')
        return redirect(url_for('todo'))

    reg_form = RegisterForm()
    if reg_form.validate_on_submit():
        user = User(email=reg_form.email.data,name=reg_form.name.data,
                 last_name=reg_form.last_name.data,password=reg_form.password.data,
                 date_added=datetime.now())
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('todo'))

    return render_template('register.html', reg_form=reg_form)


@app.route('/todo',methods=['POST','GET'])
def todo():
    if not current_user.is_authenticated:
        flash('Please login or sign up ')
        return redirect(url_for('login'))

    if request.method == 'POST':
        todo = Todo(name=request.form['todo'],user_id=current_user.id)
        todo.added = datetime.now()
        db.session.add(todo)
        db.session.commit()
        return redirect(url_for('todo'))
    return render_template('todo.html')


@app.route('/delete/<int:id>',methods=['POST'])
@login_required
def delete(id):
    if current_user.is_authenticated:
        todo = Todo.query.filter_by(id=id).first()
        db.session.delete(todo)
        db.session.commit()
        return redirect(url_for('todo'))


@app.route('/update/<int:id>',methods=['POST'])
@login_required
def update(id):
    todo = Todo.query.filter_by(id=id).first()
    todo.name = request.form['update_todo']
    todo.added = datetime.now()
    db.session.commit()
    return redirect(url_for('todo'))


@app.route('/contact',methods=['GET','POST'])
def contact():
    if request.method == 'POST':
        try:
            name = request.form['name']
            email = request.form['email']
            subject = request.form['subject']
            text = request.form['text']

            msg = Message('Contact from site', recipients=['mail@mail.com'])
            msg.body = f'Name: {name}\n Email: {email}\n Subject: {subject}\n {text}'
            mail.send(msg)
            flash('Thank You for contacting me')
            return redirect(url_for('index'))
        except:
            flash('Something went wrong, please try again')
            return redirect(url_for('contact'))
    return render_template('contact.html')


@app.route('/reset_password',methods=['POST','GET'])
def reset_password():
    if current_user.is_authenticated:
        flash('You are already logged in')
        return redirect(url_for('todo'))

    if request.method == 'POST':
        email = request.form['reset_email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = serializer.dumps(email, salt='NPpIJYdC-evIJBwpGtef')
            msg = Message('Reset Your Password',recipients=[email])
            link = url_for('new_password_set', token=token, _external=True)
            msg.body = f'Please click on link to reset Your password. This link will expire in one hour.\n {link}'
            mail.send(msg)
            flash('Email sent! Check Your email for instructions')
            return redirect(url_for('index'))

        flash('Invalid email. Please try again')
        return redirect(url_for('reset_password'))

    return render_template('reset_password.html')


@app.route('/new_password_set/<token>',methods=['POST','GET'])
def new_password_set(token):
    new_pass = NewPassword()
    try:
        email = serializer.loads(token, salt='NPpIJYdC-evIJBwpGtef', max_age=3600)
        user = User.query.filter_by(email=email).first()
        if user:
            if new_pass.validate_on_submit():
                user.password = generate_password_hash(new_pass.password.data)
                db.session.commit()
                login_user(user)
                flash('Password successfully updated')
                return redirect(url_for('index'))

    except SignatureExpired:
        flash('Your confirmation link has expired, please try again')
        return redirect(url_for('login'))

    return render_template('set_new_password.html',new_pass=new_pass)


if __name__ == '__main__':
    app.run()
