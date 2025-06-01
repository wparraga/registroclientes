"""
insecure_flask_app.py
Vulnerable Flask Web App for security practice.

Features:
- Login system (\"/\")
- User self‑registration (\"/register\")
- Clients registration form & list (\"/dashboard\")
- SQLite database (file: app.db)

Intentional vulnerabilities (for training ONLY):
1. **SQL Injection** – raw string interpolation in SQL queries.
2. **Plain‑text password storage** – no hashing/salting.
3. **Missing CSRF protection** – every state‑changing form lacks CSRF tokens.
4. **Reflected/Stored XSS** – email field rendered with the *safe* filter.
5. **Insecure session management** – weak secret key & defaults.
6. **Debug info disclosure** – app runs with debug=True by default.

Use this application **only in an isolated lab environment**. NEVER expose it to the Internet without first hardening it.
"""

from flask import Flask, request, session, redirect, url_for, render_template_string
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'changeme'  # Weak secret key – replace in production
DATABASE = 'app.db'

# ---------- Inline HTML templates (keeps project in one file) ---------- #

login_template = """
<!doctype html>
<title>Login</title>
<h2>Iniciar sesión</h2>
{% if error %}<p style='color:red;'>{{ error }}</p>{% endif %}
<form method="post">
  <label>Usuario:</label><input type="text" name="username"><br>
  <label>Contraseña:</label><input type="password" name="password"><br>
  <input type="submit" value="Entrar">
</form>
<p>¿No tienes cuenta? <a href="{{ url_for('register') }}">Regístrate</a></p>
"""

register_template = """
<!doctype html>
<title>Registro</title>
<h2>Registro de usuario</h2>
{% if error %}<p style='color:red;'>{{ error }}</p>{% endif %}
<form method="post">
  <label>Usuario:</label><input type="text" name="username"><br>
  <label>Contraseña:</label><input type="password" name="password"><br>
  <input type="submit" value="Crear cuenta">
</form>
<p><a href="{{ url_for('login') }}">← Volver al login</a></p>
"""

dashboard_template = """
<!doctype html>
<title>Panel</title>
<h2>Panel de {{ session['user'] }}</h2>
<a href="{{ url_for('logout') }}">Cerrar sesión</a>
<hr>
<h3>Registrar cliente</h3>
<form method="post">
  <label>Nombre:</label><input type="text" name="name"><br>
  <label>Email:</label><input type="text" name="email"><br>
  <input type="submit" value="Guardar">
</form>
<h3>Clientes registrados</h3>
<table border=1 cellpadding=4>
<tr><th>ID</th><th>Nombre</th><th>Email</th></tr>
{% for c in clients %}
<tr>
  <td>{{ c[0] }}</td>
  <td>{{ c[1] }}</td>
  <td>{{ c[2]|safe }}</td>  <!-- Deliberate XSS risk -->
</tr>
{% endfor %}
</table>
"""

# ---------- Helper functions ---------- #

def get_db():
    """Return a new DB connection each call."""
    return sqlite3.connect(DATABASE)

def init_db():
    """Create tables and a default admin user on first run."""
    if not os.path.exists(DATABASE):
        con = get_db()
        cur = con.cursor()
        cur.execute("CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)")
        cur.execute("CREATE TABLE clients(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT)")
        # Default credentials: admin / admin
        cur.execute("INSERT INTO users(username,password) VALUES('admin','admin')")
        con.commit()
        con.close()

# ---------- Routes ---------- #

@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # 🚨 SQL Injection vulnerable query
        con = get_db()
        cur = con.cursor()
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        cur.execute(query)
        row = cur.fetchone()
        con.close()
        if row:
            session['user'] = username  # No additional security flags
            return redirect(url_for('dashboard'))
        error = 'Credenciales inválidas'
    return render_template_string(login_template, error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            con = get_db()
            cur = con.cursor()
            # 🚨 SQL Injection vulnerable insert
            cur.execute(f"INSERT INTO users(username,password) VALUES('{username}','{password}')")
            con.commit()
            con.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            error = 'El usuario ya existe'
    return render_template_string(register_template, error=error)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        con = get_db()
        cur = con.cursor()
        # 🚨 SQL Injection vulnerable insert
        cur.execute(f"INSERT INTO clients(name,email) VALUES('{name}','{email}')")
        con.commit()
        con.close()
    con = get_db()
    cur = con.cursor()
    cur.execute("SELECT * FROM clients")
    clients = cur.fetchall()
    con.close()
    return render_template_string(dashboard_template, clients=clients, session=session)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

# ---------- Entry point ---------- #

if __name__ == '__main__':
    init_db()
    # Debug mode exposes stack traces & Werkzeug debugger (vulnerability)
    app.run(debug=True, port=5000)

"""
# Quick‑start (Linux/macOS)
# ------------------------
# python3 -m venv venv && source venv/bin/activate
# pip install Flask==2.3.2
# python insecure_flask_app.py
# Abra http://localhost:5000 en su navegador.
#
# **Advertencia:** Este código es deliberadamente inseguro. Use sólo en entornos de laboratorio.
"""
