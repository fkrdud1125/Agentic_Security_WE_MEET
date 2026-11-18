from flask import request
import flask, os, subprocess, pickle, yaml, requests
from markupsafe import Markup
from werkzeug.utils import secure_filename
q = request.args.get("q")
# ruleid: vs-py-path
flask.send_file(os.path.join("uploads", q))
# ok: vs-py-path
flask.send_from_directory("uploads", q)
