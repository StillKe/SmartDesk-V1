from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, Email
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'path/to/upload/folder'
app.config['ALLOWED_EXTENSIONS'] = {'jpg', 'jpeg', 'png', 'gif'}
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Define your models
class Blogpost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))
    author = db.Column(db.String(20))
    date_posted = db.Column(db.DateTime)
    content = db.Column(db.Text)
    image_filename = db.Column(db.String(100))

class Employee(db.Model):
    __tablename__ = 'emp'
    empid = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    address = db.Column(db.String(200))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Routes
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/home")
def home():
    return render_template('home.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('profile'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)

@app.route("/profile")
@login_required
def profile():
    return render_template('profile.html', username=current_user.username)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/blog", methods=['GET', 'POST'])
def blog():
    if request.method == 'POST':
        title = request.form.get('title')
        author = request.form.get('author')
        date_posted = datetime.strptime(request.form.get('date_posted'), '%Y-%m-%dT%H:%M')
        content = request.form.get('content')

        image = request.files.get('image')
        image_filename = None
        if image and allowed_file(image.filename):
            image_filename = image.filename
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            image.save(image_path)

        new_post = Blogpost(title=title, author=author, date_posted=date_posted, content=content, image_filename=image_filename)
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('blog'))

    posts = Blogpost.query.order_by(Blogpost.date_posted.desc()).all()
    return render_template("blog.html", posts=posts)

@app.route("/add_blogpost", methods=['GET', 'POST'])
def add_blogpost():
    if request.method == 'POST':
        title = request.form.get('title')
        author = request.form.get('author')
        date_posted = datetime.strptime(request.form.get('date_posted'), '%Y-%m-%dT%H:%M')
        content = request.form.get('content')

        image = request.files.get('image')
        image_filename = None
        if image and allowed_file(image.filename):
            image_filename = image.filename
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            image.save(image_path)

        new_post = Blogpost(title=title, author=author, date_posted=date_posted, content=content, image_filename=image_filename)
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('blog'))

    return render_template("add_blogpost.html")

@app.route("/ProgramList")
def ProgramList():
    return render_template("ProgramList.html")

@app.route("/book")
def book():
    return render_template("book.html")

@app.route("/client")
def client():
    return render_template("client.html")

@app.route("/members")
def members():
    return render_template("members.html")

@app.route("/signup")
def signup():
    return render_template("signup.html")

@app.route("/admin")
def admin():
    return render_template("admin.html")

@app.route("/StudentPortal")
def StudentPortal():
    return render_template("StudentPortal.html")

@app.route("/TeachersDashboard")
def TeachersDashboard():
    return render_template("TeachersDashboard.html")

@app.route("/ParentsDashboard")
def ParentsDashboard():
    return render_template("ParentsDashboard.html")

if __name__ == '__main__':
    app.run(debug=True)
