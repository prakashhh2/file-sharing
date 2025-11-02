import os
import secrets
import datetime
from pathlib import Path
from flask import Flask, request, redirect, url_for, render_template, flash, send_file, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Optional S3
USE_S3 = os.getenv("USE_S3", "0") == "1"
if USE_S3:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError

UPLOAD_FOLDER = Path("uploads")
UPLOAD_FOLDER.mkdir(exist_ok=True, parents=True)
ALLOWED_EXT = None  # None = allow all; you can restrict extensions if you like
MAX_CONTENT_LENGTH = 2 * 1024 * 1024 * 1024  # 2GB default max (adjust)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", secrets.token_hex(16))
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL", "sqlite:///files.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv("MAX_CONTENT_LENGTH", MAX_CONTENT_LENGTH))

db = SQLAlchemy(app)

# --- Models ---
class FileEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, index=True, nullable=False)
    filename = db.Column(db.String(512), nullable=False)
    stored_name = db.Column(db.String(512), nullable=False)  # actual storage name
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    one_time = db.Column(db.Boolean, default=False)
    downloaded = db.Column(db.Boolean, default=False)
    size = db.Column(db.BigInteger, nullable=True)

    def is_expired(self):
        if self.expires_at:
            return datetime.datetime.utcnow() > self.expires_at
        return False

# --- S3 setup (optional) ---
if USE_S3:
    S3_BUCKET = os.getenv("S3_BUCKET")
    S3_REGION = os.getenv("S3_REGION", "us-east-1")
    s3 = boto3.client("s3",
                      aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
                      aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
                      region_name=S3_REGION)

# Simple helpers
def gen_token(n=32):
    return secrets.token_urlsafe(n)[:n]

# --- Routes ---
@app.before_first_request
def init_db():
    db.create_all()

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload():
    uploaded = request.files.get("file")
    if not uploaded:
        flash("No file part", "error")
        return redirect(url_for("index"))

    # filename safe
    filename = secure_filename(uploaded.filename)
    if not filename:
        flash("Invalid filename", "error")
        return redirect(url_for("index"))

    password = request.form.get("password", "").strip()
    if not password:
        flash("Password required", "error")
        return redirect(url_for("index"))

    expire_days = request.form.get("expire_days")
    one_time = bool(request.form.get("one_time"))
    try:
        expire_days = int(expire_days) if expire_days else None
    except ValueError:
        expire_days = None

    token = gen_token(24)
    stored_name = f"{secrets.token_hex(16)}_{filename}"

    # Save file either to S3 or locally
    size = None
    if USE_S3:
        try:
            uploaded.stream.seek(0)
            s3.upload_fileobj(uploaded.stream, S3_BUCKET, stored_name)
            # Optionally set ACL or presigned
            size = None
        except (BotoCoreError, ClientError) as e:
            return f"Failed to upload to S3: {e}", 500
    else:
        path = UPLOAD_FOLDER / stored_name
        uploaded.save(path)
        size = path.stat().st_size

    pw_hash = generate_password_hash(password)
    expires_at = None
    if expire_days:
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(days=expire_days)

    entry = FileEntry(
        token=token,
        filename=filename,
        stored_name=stored_name,
        password_hash=pw_hash,
        expires_at=expires_at,
        one_time=one_time,
        size=size
    )
    db.session.add(entry)
    db.session.commit()

    link = url_for("download_token", token=token, _external=True)
    return render_template("uploaded.html", link=link, token=token, expires_at=expires_at, one_time=one_time)

@app.route("/f/<token>", methods=["GET", "POST"])
def download_token(token):
    entry = FileEntry.query.filter_by(token=token).first_or_404()
    if entry.is_expired():
        return render_template("download.html", error="This link has expired."), 410

    if entry.one_time and entry.downloaded:
        return render_template("download.html", error="This file was already downloaded (one-time)."), 410

    if request.method == "GET":
        # Show password entry form
        return render_template("download.html", token=token, filename=entry.filename)

    # POST: check password and serve
    password = request.form.get("password", "")
    if not check_password_hash(entry.password_hash, password):
        return render_template("download.html", token=token, filename=entry.filename, error="Incorrect password."), 403

    # Mark downloaded if one-time
    if entry.one_time:
        entry.downloaded = True
        db.session.commit()

    if USE_S3:
        # Generate presigned url and redirect
        presigned = s3.generate_presigned_url('get_object',
                                              Params={'Bucket': S3_BUCKET, 'Key': entry.stored_name},
                                              ExpiresIn=60)  # short-lived
        return redirect(presigned)
    else:
        path = UPLOAD_FOLDER / entry.stored_name
        if not path.exists():
            abort(404)
        # send_file will stream safely
        return send_file(path, as_attachment=True, download_name=entry.filename)

# Optional API endpoint for programmatic upload (returns JSON)
@app.route("/api/upload", methods=["POST"])
def api_upload():
    uploaded = request.files.get("file")
    if not uploaded:
        return jsonify({"error":"no file"}), 400
    filename = secure_filename(uploaded.filename)
    password = request.form.get("password","")
    if not password:
        return jsonify({"error":"password required"}), 400

    token = gen_token(24)
    stored_name = f"{secrets.token_hex(16)}_{filename}"
    if USE_S3:
        uploaded.stream.seek(0)
        s3.upload_fileobj(uploaded.stream, S3_BUCKET, stored_name)
    else:
        (UPLOAD_FOLDER / stored_name).write_bytes(uploaded.read())

    pw_hash = generate_password_hash(password)
    entry = FileEntry(token=token, filename=filename, stored_name=stored_name, password_hash=pw_hash)
    db.session.add(entry)
    db.session.commit()
    link = url_for("download_token", token=token, _external=True)
    return jsonify({"link":link, "token":token})

# Simple health check
@app.route("/health")
def health():
    return "OK"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
