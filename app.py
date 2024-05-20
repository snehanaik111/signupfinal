from flask import Flask, request, render_template, redirect, session, url_for
import bcrypt
import pypyodbc as odbc
import pandas as pd 

app = Flask(__name__)
app.secret_key = 'secret_key'


server = 'mydemo121.database.windows.net'
database = 'sampledb'
connection_string = 'Driver={ODBC Driver 18 for SQL Server};Server=tcp:mydemo121.database.windows.net,1433;Database=sampledb;Uid=samiksha;Pwd=Sneha@16;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # Create the 'login' table if it doesn't exist
        conn = odbc.connect(connection_string)
        cursor = conn.cursor()
        cursor.execute("""
            IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='login' AND xtype='U')
            CREATE TABLE dbo.login (
                id INT IDENTITY(1,1) PRIMARY KEY NOT NULL,
                name VARCHAR(50) NOT NULL,
                email VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL
            )
        """)
        conn.commit()

        # Check if the email already exists in the database
        cursor.execute("SELECT * FROM dbo.login WHERE email = ?", (email,))
        existing_user = cursor.fetchone()
        if existing_user:
            error = 'Email is already registered.'
        else:
            # Create a new user and add it to the database
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            cursor.execute("INSERT INTO dbo.login (name, email, password) VALUES (?, ?, ?)",
                           (name, email, hashed_password))
            conn.commit()
            
            return redirect('/login')

        conn.close()

    return render_template('signup.html', error=error)
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = odbc.connect(connection_string)
        cursor = conn.cursor()

        # Fetch only the necessary columns
        cursor.execute("SELECT email, password FROM dbo.login WHERE email = ?", (email,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
            session['email'] = user[0]  # Store the email in session
            conn.close()
            return redirect('/dashboard')
        else:
            error = 'Please provide valid credentials to login.'

        conn.close()

    return render_template('login.html', error=error)


@app.route('/dashboard')
def dashboard():
    if 'email' in session:
        email = session['email']
        conn = odbc.connect(connection_string)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM dbo.login WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()
        print("User:", user)  # Add this line for debugging
        return render_template('dashboard.html', user=user)
    
    return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect('/login')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
