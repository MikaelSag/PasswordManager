from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
from dotenv import load_dotenv
import MySQLdb.cursors, uuid, base64, os

from Password_hashing import hash_password, verify_password
from encryption import derive_key, encrypt_vault_entry, decrypt_vault_entry

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(32))

app.config['MYSQL_HOST'] = os.getenv("MYSQL_HOST", "localhost")
app.config['MYSQL_PORT'] = int(os.getenv("MYSQL_PORT", 3306))
app.config['MYSQL_USER'] = os.getenv("MYSQL_USER")
app.config['MYSQL_PASSWORD'] = os.getenv("MYSQL_PASSWORD")
app.config['MYSQL_DB'] = os.getenv("MYSQL_DATABASE")

mysql = MySQL(app)

@app.route("/", methods=['GET', 'POST'])
def index():
    if "userID" not in session:
        return redirect(url_for('login'))

    if request.method == 'GET':
        passwords = []
        userID = session.get('userID')
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        selected_category = request.args.get('category')

        if not selected_category or selected_category == 'All':
            cursor.execute('SELECT * FROM vault WHERE user_userID = %s', (userID,))
        else:
            cursor.execute(
                'SELECT * FROM vault WHERE user_userID = %s AND serviceCategory = %s',
                (userID, selected_category)
            )

        for row in cursor.fetchall():
            passwords.append({
                "passwordID": row["entryID"],
                "site": row["serviceName"],
                "username": row["serviceUsername"],
                "password": "••••••••",
                "category": row["serviceCategory"],
                "tag": {
                    "label": row["serviceTag"],
                    "color": tag_color(row["serviceTag"])
                }
            })

        categories = ["All", "Banking", "Social Media", "Work", "Other"]
        return render_template("index.html", passwords=passwords, categories=categories, show_add=True)

    passID = request.form['password_id']
    action = request.form['action']

    if action == 'delete':
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('DELETE FROM vault WHERE entryID = %s', (passID,))
        mysql.connection.commit()
        return redirect(url_for('index'))

    if action == 'edit':
        session['passID'] = passID
        return redirect(url_for('edit_password'))

    return redirect(url_for('index'))


def tag_color(tag):
    match tag:
        case 'Important':
            return "bg-pink-200"
        case 'Work':
            return "bg-purple-200"
        case 'Personal':
            return "bg-green-200"
        case 'Side Project':
            return "bg-yellow-200"


@app.route("/add", methods=['GET','POST'])
def add_password():
    if "userID" not in session:
        return redirect(url_for('login'))

    if request.method == "POST":
        entryID = uuid.uuid4()
        site = request.form["site"]
        username = request.form["username"]
        userID = session.get('userID')
        vault_password = request.form["password"]
        category = request.form["category"]
        tag = request.form["tag"]

        key = base64.b64decode(session['key'])
        encrypted = encrypt_vault_entry(key, vault_password)

        ciphertext = encrypted["ciphertext"]
        nonce = encrypted["nonce"]

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'INSERT INTO vault (entryID, user_userID, serviceUsername, serviceName, serviceCategory, encryptPassword, nonce, serviceTag) '
            'VALUES (%s, %s, %s, %s, %s, %s, %s, %s)',
            (entryID, userID, username, site, category, ciphertext, nonce, tag)
        )
        mysql.connection.commit()

        return render_template("add_password.html", msg='Added password successfully')

    return render_template("add_password.html")


@app.route("/view/<entryID>")
def view_password(entryID):
    if "userID" not in session:
        return redirect(url_for('login'))

    userID = session['userID']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute(
        'SELECT encryptPassword, nonce FROM vault WHERE entryID=%s AND user_userID=%s',
        (entryID, userID)
    )
    row = cursor.fetchone()
    if row is None:
        return "Entry not found", 404

    key = base64.b64decode(session['key'])
    decrypted = decrypt_vault_entry(key, {
        "ciphertext": row["encryptPassword"],
        "nonce": row["nonce"]
    })

    return render_template("view_password.html", password=decrypted)


@app.route("/edit_password", methods=['GET','POST'])
def edit_password():
    if "userID" not in session:
        return redirect(url_for('login'))

    passID = session.get('passID')
    if not passID:
        return redirect(url_for('index'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM vault WHERE entryID = %s', (passID,))
    pw = cursor.fetchone()

    if request.method == "POST":
        site = request.form["site"]
        username = request.form["username"]
        new_password = request.form["password"]
        category = request.form["category"]
        tag = request.form["tag"]

        key = base64.b64decode(session['key'])
        encrypted = encrypt_vault_entry(key, new_password)

        ciphertext = encrypted["ciphertext"]
        nonce = encrypted["nonce"]

        cursor.execute(
            'UPDATE `vault` SET serviceUsername=%s, serviceName=%s, serviceCategory=%s, encryptPassword=%s, `nonce`=%s, serviceTag=%s '
            'WHERE entryID = %s',
            (username, site, category, ciphertext, nonce, tag, passID)
        )
        cursor.connection.commit()
        session.pop('passID', None)
        return redirect(url_for('index'))

    return render_template("edit_password.html", pw=pw)


@app.route("/login", methods=['GET','POST'])
def login():
    if request.method == "POST":
        username = request.form["username"]
        login_password = request.form["password"]

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user WHERE username = %s', (username,))
        user = cursor.fetchone()

        if user is None:
            return render_template('login.html', msg="Login failed")

        if not verify_password(user['loginPsswd'], login_password):
            return render_template('login.html', msg="Login failed")

        key = derive_key(login_password, user['salt'])
        session['key'] = base64.b64encode(key).decode()
        session['userID'] = user['userID']

        return redirect(url_for('index'))

    return render_template('login.html')


@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        pw1 = request.form["password"]
        pw2 = request.form["confPassword"]

        if pw1 != pw2:
            return render_template('register.html', msg="Registration failed")

        salt = os.urandom(16)
        hashed = hash_password(pw1)

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'INSERT INTO user (username, loginPsswd, salt) VALUES (%s, %s, %s)',
            (username, hashed, salt)
        )
        mysql.connection.commit()

        return redirect(url_for('login'))

    return render_template('register.html')


@app.route("/logout")
def logout():
    session.clear()
    return render_template('logout.html', delay=3)


if __name__ == "__main__":
    app.run(debug=True)
