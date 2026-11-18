"""Inert synthetic source fixtures. Never import or run this application."""
from flask import Flask, request, send_file, render_template_string
from flask_cors import CORS
from markupsafe import Markup, escape
from sqlalchemy import text
from werkzeug.utils import secure_filename
import os, subprocess, pickle, yaml, jwt, requests

app = Flask(__name__)
# GT: P01 CI-16 vulnerable
SECRET_KEY = "dev"
# GT: P02 V-02 vulnerable
CORS(app)
# GT: P03 CI-05 vulnerable
OPENAI_KEY = "synthetic-credential-98765"
# GT: P04 CI-05 vulnerable
aws = "AKIAABCDEFGHIJKLMNOP"
# GT: P05 CI-05 vulnerable
url = "postgresql://sample:synthetic-password@localhost/demo"

def queries(db):
    q = request.args.get('q')
    # GT: P06 CI-02 vulnerable
    db.execute(f"SELECT * FROM notes WHERE id={q}")
    query = "select * from notes where id='" + q + "'"
    # GT: P07 CI-02 vulnerable
    db.execute(query)
    # GT: P08 CI-02 vulnerable
    db.execute("DELETE FROM notes WHERE id=%s" % q)
    # GT: P09 CI-02 vulnerable
    db.execute(text("UPDATE notes SET title='{}'".format(q)))
    # GT: S01 CI-02 safe
    db.execute("SELECT * FROM notes WHERE id=?", (q,))

def dangerous():
    q = request.args.get('q')
    # GT: P10 CI-01 vulnerable
    render_template_string('<p>' + q)
    # GT: P11 CI-06 vulnerable
    Markup('<p>%s' % q)
    # GT: P12 CI-01 vulnerable
    subprocess.run('echo ' + q, shell=True)
    # GT: P13 CI-01 vulnerable
    eval(q)
    # GT: P14 CI-15 vulnerable
    send_file(os.path.join('files', q))
    # GT: P15 CI-08 vulnerable
    requests.get(q)
    # GT: P16 CI-01 vulnerable
    pickle.loads(request.data)
    # GT: P17 CI-01 vulnerable
    yaml.load(q, Loader=yaml.Loader)
    # GT: P18 CI-16 vulnerable
    jwt.decode(q, options={'verify_signature': False})
    f = request.files['file']
    # GT: P19 CI-14 vulnerable
    f.save(os.path.join('uploads', f.filename))
    # GT: S02 CI-06 safe
    Markup(escape(q))
    # GT: S03 CI-01 safe
    subprocess.run(['echo', q], shell=False)
    # GT: S04 CI-15 safe
    send_file(os.path.join('files', secure_filename(q)))
    # GT: S05 CI-08 safe
    requests.get('https://example.invalid')
    # GT: S06 CI-01 safe
    yaml.safe_load(q)
    # GT: S07 CI-16 safe
    jwt.decode(q, signing_key, algorithms=['HS256'])
    # GT: S08 CI-14 safe
    f.save(os.path.join('uploads', secure_filename(f.filename)))

@app.get('/admin/users')
# GT: P20 CI-19 vulnerable
def admin_users():
    return 'users'

@app.get('/orders/<int:order_id>')
# GT: P21 CI-11 vulnerable
def order(order_id):
    return db.query(order_id)

def cookie(response):
    # GT: P22 CI-18 vulnerable
    response.set_cookie('role', request.args.get('role'))
    # GT: S09 CI-18 safe
    response.set_cookie('session', value, secure=True, httponly=True, samesite='Lax')

# GT: P23 CI-04 vulnerable
app.run(debug=True, host='0.0.0.0')
# GT: S10 CI-04 safe
app.run(debug=False)

@app.get('/admin/safe')
@login_required
# GT: S11 CI-19 safe
def safe_admin():
    return 'users'

@app.get('/orders/<int:order_id>')
@login_required
# GT: S12 CI-11 safe
def safe_order(order_id):
    return db.query(order_id).filter(owner_id=current_user.id)

# GT: S13 CI-05 safe
OPENAI_KEY = os.environ['OPENAI_KEY']
# GT: S14 CI-16 safe
SECRET_KEY = os.environ['SESSION_SECRET']
# GT: S15 V-02 safe
CORS(app, origins=['https://example.invalid'])
