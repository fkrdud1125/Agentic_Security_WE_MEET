from flask import request
import flask, os, subprocess, pickle, yaml, requests
from markupsafe import Markup
from werkzeug.utils import secure_filename
q = request.args.get("q")
# ruleid: vs-py-code
eval(q)
# ok: vs-py-code
subprocess.run(["echo", q], shell=False)
