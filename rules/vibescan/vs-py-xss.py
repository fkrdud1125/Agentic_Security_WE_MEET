from flask import request
import flask, os, subprocess, pickle, yaml, requests
from markupsafe import Markup
from werkzeug.utils import secure_filename
q = request.args.get("q")
# ruleid: vs-py-xss
Markup("<b>%s</b>" % q)
# ok: vs-py-xss
Markup("<b>fixed</b>")
