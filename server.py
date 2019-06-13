from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
import re

app = Flask(__name__)
bcrypt = Bcrypt(app)

app.secret_key = "Victoria's Secret"
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

USER_KEY = "user_id"

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/register', methods=["POST"])
def register():
    is_valid = True
    if len(request.form['first_name']) < 1:
        is_valid = False
        flash("Please insert a First Name")
    if len(request.form['last_name']) < 1:
        is_valid = False
        flash("Please insert a Last Name")
    if not EMAIL_REGEX.match(request.form['email']):
        is_valid = False
        flash("Please insert an email address")
    # if len(request.form['password']) < 1:
    #     is_valid = False
    #     flash("Please insert a password")
    # if len(request.form['confirmation_password']) < 1:
    #     is_valid = False
    #     flash("Please insert a password")

    if not is_valid:
        return redirect('/')
    else:
        hashed_password = bcrypt.generate_password_hash(request.form['password'])
        string_password = request.form['confirmation_password']
        passMatch = bcrypt.check_password_hash(hashed_password, string_password)

        if passMatch:
            mysql = connectToMySQL('login_and_registration')
            query = 'INSERT INTO users (first_name, last_name, email, password) VALUES (%(fname)s, %(lname)s, %(email)s, %(password)s);'
            data = {
                'fname' : request.form['first_name'],
                'lname' : request.form['last_name'],
                'email' : request.form['email'],
                'password' : hashed_password
            }
            user_id = mysql.query_db(query, data)
            session[USER_KEY] = user_id
            return redirect('/success')
    # return redirect('/')

@app.route('/success')
def successful_login():    
    mysql = connectToMySQL('login_and_registration')
    data = {
        'id' : session[USER_KEY]
    }
    query = 'SELECT * FROM users WHERE id = %(id)s'
    user_id = mysql.query_db(query, data)
    return render_template('success.html', user=user_id)


@app.route('/login', methods=["POST"])
def login():
    mysql = connectToMySQL('login_and_registration')
    query = 'SELECT id, password FROM users WHERE email = %(em)s';
    data = {
        'em' : request.form['email']
    }
    user_id = mysql.query_db(query, data)  
    print(user_id)
    string_password = request.form['password']  
    if bcrypt.check_password_hash(user_id[0]['password'], string_password):
        session[USER_KEY] = user_id[0]['id']
        return redirect('/success')

@app.route('/logout')
def logout():
    return redirect('/')

if __name__=="__main__":
    app.run(debug=True)