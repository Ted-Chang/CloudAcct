# -*- coding: utf-8 -*-
"""
    CloudAcct

    copyright(c) 2017 Ted Zhang.
    All rights reserved.
"""
import os
import time
from sqlite3 import dbapi2 as sqlite3
from datetime import datetime
from flask import Flask, request, render_template, g, redirect, \
     url_for, abort, session, _app_ctx_stack, flash
from werkzeug import generate_password_hash, check_password_hash

# Configuration
DATABASE = '/tmp/cloud_acct.db'
DEBUG = True
SECRET_KEY = b'_6#y9L"F7Q3z\n\xec]/'

# create our application
app = Flask('__name__')
app.config.from_object(__name__)
app.config.from_envvar('CLOUDACCT_SETTINGS', silent=True)

def init_db():
    """Initialize the database."""
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()

@app.cli.command('initdb')
def initdb_command():
    """Creates the database tables."""
    init_db()
    print('Database initialized.')

def get_db():
    """
    Opens a new database connection if there is none yet for the
    current application context.
    """
    top = _app_ctx_stack.top
    if not hasattr(top, 'sqlite_db'):
        top.sqlite_db = sqlite3.connect(app.config['DATABASE'])
        top.sqlite_db.row_factory = sqlite3.Row
    return top.sqlite_db

def query_db(query, args=(), one=False):
    """Queries the database and returns a list of dictionaries."""
    cur = get_db().execute(query, args)
    ret = cur.fetchall()
    return (ret[0] if ret else None) if one else ret

@app.teardown_appcontext
def close_database(exception):
    """Closes the database again at the end of the request."""
    top = _app_ctx_stack.top
    if hasattr(top, 'sqlite_db'):
        top.sqlite_db.close()

def format_datetime(timestamp):
    """Format a timestamp for display."""
    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d @ %H:%M')

def get_user_id(username):
    """Look up the id for a username."""
    ret = query_db('select user_id from user where username = ?',
                   [username], one=True)
    return ret[0] if ret else None

@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        g.user = query_db('select * from user where user_id = ?', 
                          [session['user_id']], one=True)

@app.route('/')
def view():
    if not g.user:
        return redirect(url_for('public_view'))
    error = None
    return render_template('view.html', error=error)

@app.route('/public')
def public_view():
    """Displays the latest view of all users."""
    error = None
    return render_template('view.html', error=error)

@app.route('/<username>')
def user_view(username):
    """Displays a user's view."""
    profile_user = None
    if profile_user is None:
        abort(404)
    return render_template('view.html', profile_user=profile_user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register the user."""
    if g.user:
        return redirect(url_for('view'))
    error = None
    if request.method == 'POST':
        if not request.form['username']:
            error = 'You have to enter a username'
        elif not request.form['email'] or '@' not in request.form['email']:
            error = 'You have to enter a valid email address'
        elif not request.form['password']:
            error = 'You have to enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'The tow passwords do not match'
        elif get_user_id(request.form['username']) is not None:
            error = 'The username is already taken'
        else:
            db = get_db()
            db.execute('''insert into user (
                       username, email, pw_hash) values (?, ?, ?)''', 
                       [request.form['username'], request.form['email'],
                        generate_password_hash(request.form['password'])])
            db.commit()
            flash('You were successfully registered!')
            return redirect(url_for('login'))
    return render_template('register.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Logs the user in."""
    if g.user:
        return redirect(url_for('view'))
    error = None
    if request.method == 'POST':
        user = query_db('''select * from user where username = ?''',
                        [request.form['username']], one=True)
        if user is None:
            error = 'Invalid username'
        elif not check_password_hash(user['pw_hash'],
                                     request.form['password']):
            error = 'Incorrect password'
        else:
            flash('You were logged in!')
            session['user_id'] = user['user_id']
            return redirect(url_for('view'))
    return render_template('login.html', error=error)

@app.route('/forget_passwd', methods=['GET', 'POST'])
def forget_passwd():
    """Get back the user password."""
    if g.user:
        return redirect(url_for('view'))
    error = None
    if request.method == 'POST':
        if not request.form['username']:
            error = 'You have to enter a username'
        elif get_user_id(request.form['username']) is None:
            error = 'User not exists!'
        elif not request.form['email']:
            email = query_db('''select email from user where username = ?''',
                             [request.form['username']], one=True)
            if email != request.form['email']:
                error = 'Email address not match!'
        else:
            db = get_db()
            new_passwd = '123456' # Replace this with random password
            db.execute('''update user set pw_hash = ? where username = ?''', 
                       [generate_password_hash(new_passwd), 
                        request.form['username']])
            db.commit()
            flash('Your new password was sent, please check your email!')
            return redirect(url_for('login'))
    return render_template('forgetpasswd.html', error=error)

@app.route('/logout')
def logout():
    """Logs the user out."""
    flash('You were logged out!')
    session.pop('user_id', None)
    return redirect(url_for('public_view'))

port = os.getenv('PORT', '8080')
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(port))
