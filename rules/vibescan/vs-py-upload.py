from flask import request
from werkzeug.utils import secure_filename
import os
f = request.files["file"]
# ruleid: vs-py-upload
f.save(os.path.join("uploads", f.filename))
# ok: vs-py-upload
f.save(os.path.join("uploads", secure_filename(f.filename)))
