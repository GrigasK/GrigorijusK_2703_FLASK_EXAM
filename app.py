import os
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import sqlite3

from flask_login import LoginManager, UserMixin, current_user, logout_user, login_user, login_required
import forms

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = '4654f5dfadsrfasdr54e6rae'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + \
    os.path.join(basedir, 'expenses.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.login_message = "Login if you want to see the information"


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)


class ExpenseGroup(db.Model):
    __tablename__ = 'expense_groups'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    group_name = db.Column(db.String(50), nullable=False)


class Expense(db.Model):
    __tablename__ = 'expenses'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey(
        'expense_groups.id'), nullable=False)
    expense_description = db.Column(db.String(50), nullable=False)
    expense_amount = db.Column(db.Float, nullable=False)


@login_manager.user_loader
def load_user(user_id):
    db.create_all()
    return User.query.get(int(user_id))


conn = sqlite3.connect("expenses.db", check_same_thread=False)
conn.row_factory = sqlite3.Row


def fetch_users():
    users_table = conn.execute("SELECT * FROM users").fetchall()

    return users_table


def fetch_groups():
    groups_table = conn.execute("SELECT * FROM expense_groups").fetchall()
    groups = groups_table
    return groups


def fetch_expenses():
    expenses_table = conn.execute("SELECT * FROM expenses").fetchall()
    expenses = expenses_table
    return expenses


@app.route("/register", methods=['GET', 'POST'])
def register():
    db.create_all()
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = forms.RegisterForm()
    if form.validate_on_submit():
        encripted_password = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')
        user = User(
            name=form.name.data, password=encripted_password, email=form.email.data)
        db.session.add(user)
        db.session.commit()
        flash('You successfuly registered, please log on', 'success')
        return redirect(url_for('index'))
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    db.create_all()
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = forms.LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(
            email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('group'))
        else:
            flash('Something went wrong, please check your email and password', 'danger')
    return render_template('login.html', title='login', form=form)


@app.route("/group")
@login_required
def group():
    db.create_all()
    try:
        all_groups = ExpenseGroup.query.filter_by(
            user_id=current_user.id).all()
    except:
        all_groups = []
    return render_template("group.html", groups_table=all_groups)


@app.route("/new_group", methods=["GET", "POST"])
@login_required
def new_group():
    group_name = request.form['group_name']

    new_group = ExpenseGroup(group_name=group_name,
                             user_id=current_user.id)
    db.session.add(new_group)
    db.session.commit()
    flash(f"Group created", 'success')
    return redirect(url_for('group'))


@app.route("/bills/<int:id>", methods=['GET', 'POST'])
@login_required
def bill(id):
    bill = Expense.query.filter_by(group_id=id).all()

    return render_template("bills.html", bill=bill, id=id)


@app.route("/new_bill", methods=["POST"])
@login_required
def new_bill():
    description = request.form['expense_description']
    amount = request.form['expense_amount']
    group_id = request.form['group_id']

    new_bill = Expense(expense_description=description,
                       user_id=current_user.id, expense_amount=amount, group_id=group_id)
    db.session.add(new_bill)
    db.session.commit()
    flash(f"New bill added", 'success')
    return redirect(url_for('bill', id=group_id))


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route("/")
def index():
    return redirect(url_for("login"))


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8000, debug=True)
    db.create_all()
