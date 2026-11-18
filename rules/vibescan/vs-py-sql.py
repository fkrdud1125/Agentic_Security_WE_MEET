from flask import request
import flask, os, subprocess, pickle, yaml, requests
from markupsafe import Markup
from werkzeug.utils import secure_filename
q = request.args.get("q")
# ruleid: vs-py-sql
db.execute(f"SELECT * FROM notes WHERE id={q}")
# ok: vs-py-sql
db.execute("SELECT * FROM notes WHERE id=?", (q,))
