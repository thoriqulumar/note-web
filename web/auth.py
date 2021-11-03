from flask import render_template, Blueprint, request, flash, redirect, url_for
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)

@auth.route('/signup', methods=['GET', 'POST'])
def signup():
	if request.method == 'POST':
		email = request.form.get('email-signup')
		name = request.form.get('name-signup')
		password = request.form.get('password-signup')
		confirm_password = request.form.get('confirm-password-signup')

		user = User.query.filter_by(email=email).first()
		print(user)
		if user:
			flash('Email already exists', category='error')
		elif len(email) == 0:
			flash('Email is required', category='error')
		elif len(email) < 4:
			flash('Email must greater than 3 characters', category='error')
		elif password != confirm_password:
			flash('Password don\'t match', category='error')
		elif len(str(password)) == 0:
			flash('Password is required', category='error')
		elif len(str(confirm_password)) == 0:
			flash('Comfirm password is required', category='error')
		elif len(password) < 8:
			flash('Password must at least 8 characters', category='error')
		else:
			new_user = User(name=name, email=email, password=generate_password_hash(password, method='sha256'))
			db.session.add(new_user)
			db.session.commit()
			login_user(new_user, remember=True)
			flash('account created', category='success')
			return redirect(url_for('views.home'))

	return render_template('sign-up.html', user=current_user)

@auth.route('/signin', methods=['GET', 'POST'])
def signin():
	if request.method == 'POST':
		email = request.form.get('email')
		password = request.form.get('password')
		user = User.query.filter_by(email=email).first()
		if user:
			if check_password_hash(user.password, password):
				flash('Logged in successfully!', category='success')
				login_user(user, remember=True)
				return redirect(url_for('views.home'))
			else:
				flash('Incorrect password, try again.', category='error')
		else:
			flash('Email does not exist.', category='error')

	return render_template("sign-in.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('views.main'))