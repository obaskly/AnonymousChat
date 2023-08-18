from flask import Flask, render_template, redirect, url_for, flash, session, request, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_bcrypt import Bcrypt
from flask_session import Session
from wtforms import StringField, SelectField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, ValidationError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import InvalidToken
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timedelta
from redis.exceptions import RedisError
from urllib.parse import quote_plus
import os
import base64
import redis


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(32)
app.config['WTF_CSRF_ENABLED'] = True
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = False
app.config['DEBUG'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'chat:'
redis_password = os.environ.get('REDIS_PASSWORD')
encoded_password = quote_plus(redis_password)
app.config['SESSION_REDIS'] = redis.StrictRedis(host='localhost', port=6379, db=0, password=redis_password)
Session(app)
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
REDIS_SESSION_KEY_PREFIX = "session_key:"
SESSION_KEY_EXPIRY = 5 * 60

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri=f"redis://:{encoded_password}@localhost:6379"
)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    public_key = db.Column(db.String(5000), nullable=True)
    encrypted_private_key = db.Column(db.String(9000), unique=True, nullable=True)
    salt = db.Column(db.String(120), nullable=True)

    sent_messages = db.relationship('Message', backref='sender', lazy=True, foreign_keys='Message.sender_id')
    received_messages = db.relationship('Message', backref='recipient', lazy=True, foreign_keys='Message.recipient_id')

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    def get_id(self):
        return str(self.id)

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    encrypted_content = db.Column(db.String(5000), nullable=False)
    encrypted_key = db.Column(db.String(9000), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    lifespan = db.Column(db.Integer)


def password_complexity(form, field):
    password = field.data
    if not any(char.isdigit() for char in password):
        raise ValidationError('Password should contain at least one numeral.')
    if not any(char.isalpha() for char in password):
        raise ValidationError('Password should contain at least one letter.')
    if not any(char in '!@#$%^&*()-+=[]{}|;:,.<>?/\\' for char in password):
        raise ValidationError('Password should contain at least one special character.')


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(min=15, max=90)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=10, max=20), password_complexity])
    submit = SubmitField('Sign Up')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=10, max=20), password_complexity])
    submit = SubmitField('Login')


class MessageForm(FlaskForm):
    content = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send')
    recipient = StringField('Recipient', validators=[DataRequired()])
    hours = SelectField('Hours', choices=[(str(i), str(i)) for i in range(25)], default='0')
    minutes = SelectField('Minutes', choices=[(str(i), str(i)) for i in range(60)], default='0')
    seconds = SelectField('Seconds', choices=[(str(i), str(i)) for i in range(60)], default='0')

    def validate(self, **kwargs):
        rv = super(MessageForm, self).validate(**kwargs)
        if not rv:
            return False

        if self.hours.data == '0' and self.minutes.data == '0' and self.seconds.data == '0':
            self.hours.errors.append('Please select a self-destruct time.')
            return False

        return True


def set_session_key_in_redis(username, session_key):
    try:
        app.config['SESSION_REDIS'].setex(REDIS_SESSION_KEY_PREFIX + username, SESSION_KEY_EXPIRY, session_key)
    except RedisError:
        flash('error', 'Internal server error. Please try again.')
        return False
    return True


def get_session_key_from_redis(username):
    try:
        return app.config['SESSION_REDIS'].get(REDIS_SESSION_KEY_PREFIX + username)
    except RedisError:
        flash('error', 'Internal server error. Please try again.')
        return None


def get_or_refresh_session_key(username):
    session_key = get_session_key_from_redis(username)
    if not session_key:
        session_key = generate_session_key()
        if not set_session_key_in_redis(username, session_key):
            return None
    return session_key


def generate_session_key():
    return os.urandom(32)


def derive_key(password, salt=None):
    if not salt:
        salt = os.urandom(16)
    else:
        salt = bytes.fromhex(salt)

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key, salt.hex()


@app.errorhandler(ValidationError)
def handle_csrf_error(e):
    return "Something went wrong.", 400


@app.errorhandler(404)
def handle_404_error(e):
    logout_user()
    return redirect(url_for('welcome'))


@app.errorhandler(503)
def handle_503_error(e):
    logout_user()
    return redirect(url_for('welcome'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.before_request
def before_request():
    g.nonce = os.urandom(16).hex()


@app.after_request
def add_security_headers(response):
    csp = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{g.nonce}'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com;"
    )
    response.headers['Content-Security-Policy'] = csp
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter((User.username == form.username.data) | (User.email == form.email.data)).first()
        if existing_user:
            if existing_user.username == form.username.data:
                flash('error', 'Username already taken')
                form.username.errors.append("Username already taken")
            if existing_user.email == form.email.data:
                flash('error', 'Email already registered')
                form.email.errors.append("Email already registered")
            return render_template('register.html', form=form)

        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        user.public_key = public_key_pem

        encrypted_private_key, salt = encrypt_key(private_key_pem.encode(), form.password.data)
        user.encrypted_private_key = encrypted_private_key
        user.salt = salt

        try:
            db.session.add(user)
            db.session.commit()
            flash('success', 'Registration successful!')
            return redirect(url_for('login'))
        except Exception as e:
            print(e)
            db.session.rollback()
            flash('error', 'An error occurred. Please try again.')
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            session.permanent = True
            salt = user.salt
            decrypted_private_key = decrypt_key(user.encrypted_private_key, form.password.data, salt).decode()

            session_key = get_or_refresh_session_key(user.username)
            if not session_key:
                return render_template('login.html', form=form)

            session['session_key'] = session_key
            cipher = Fernet(base64.urlsafe_b64encode(session_key))
            encrypted_private_key_for_session = cipher.encrypt(decrypted_private_key.encode())

            session['encrypted_private_key_for_session'] = encrypted_private_key_for_session

            return redirect(url_for('chat'))
        else:
            flash('error', 'Invalid username or password')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('encrypted_private_key_for_session', None)
    return redirect(url_for('welcome'))


@app.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    form = MessageForm()
    session_key = get_or_refresh_session_key(current_user.username)
    if not session_key:
        flash('error', 'Session expired. Please login again.')
        return redirect(url_for('logout'))

    encrypted_private_key_for_session = session.get('encrypted_private_key_for_session')

    if not encrypted_private_key_for_session:
        flash('error', 'Please login again.')
        return redirect(url_for('logout'))

    try:
        cipher = Fernet(base64.urlsafe_b64encode(session_key))
        decrypted_private_key = cipher.decrypt(encrypted_private_key_for_session)
    except InvalidToken:
        flash('error', 'Invalid session. Please login again.')
        logout_user()
        return redirect(url_for('login'))

    if form.validate_on_submit():
        fernet_key = generate_fernet_key()
        encrypted_message = encrypt_message_with_fernet_key(form.content.data, fernet_key)

        recipient = User.query.filter_by(username=form.recipient.data).first()
        if not recipient or not recipient.public_key:
            flash('error', 'Recipient not found.')
            return redirect(url_for('chat'))

        recipient_public_key = recipient.public_key
        encrypted_key = encrypt_fernet_key_with_rsa(fernet_key, recipient_public_key)

        message = Message(encrypted_content=encrypted_message, encrypted_key=encrypted_key, sender_id=current_user.id, recipient_id=recipient.id)
        lifespan_seconds = int(form.hours.data) * 3600 + int(form.minutes.data) * 60 + int(form.seconds.data)
        message.lifespan = lifespan_seconds

        db.session.add(message)
        db.session.commit()
        flash('success', 'Message sent!')
        return redirect(url_for('chat'))

    messages = Message.query.filter_by(recipient_id=current_user.id).all()
    decrypted_messages = []

    for message in messages:
        decrypted_key = decrypt_fernet_key_with_rsa(message.encrypted_key, decrypted_private_key)
        decrypted_message = decrypt_message_with_fernet_key(message.encrypted_content, decrypted_key)
        sender_username = User.query.get(message.sender_id).username
        formatted_message = f"{sender_username}: {decrypted_message}"
        decrypted_messages.append(formatted_message)

    return render_template('chat.html', form=form, messages=decrypted_messages)


@app.route('/')
def welcome():
    return render_template('welcome.html')


@app.errorhandler(429)
def ratelimit_error(e):
    flash('error', 'Too many requests. Please wait a moment and try again.')

    if request.endpoint == 'login':
        return render_template('login.html', form=LoginForm()), 429
    elif request.endpoint == 'register':
        return render_template('register.html', form=RegistrationForm()), 429
    else:
        return render_template('welcome.html'), 429


def encrypt_key(key, password, salt=None):
    derived_key, derived_salt = derive_key(password, salt)
    cipher = Fernet(base64.urlsafe_b64encode(derived_key))
    encrypted = cipher.encrypt(key)
    return encrypted, derived_salt


def decrypt_key(encrypted_key, password, salt):
    derived_key = derive_key(password, salt)[0]
    cipher = Fernet(base64.urlsafe_b64encode(derived_key))
    decrypted = cipher.decrypt(encrypted_key)
    return decrypted


def generate_fernet_key():
    return Fernet.generate_key()


def encrypt_message_with_fernet_key(message, key):
    cipher = Fernet(key)
    return cipher.encrypt(message.encode())


def decrypt_message_with_fernet_key(encrypted_message, key):
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_message).decode()


def encrypt_fernet_key_with_rsa(fernet_key, public_key_pem):
    public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
    encrypted_key = public_key.encrypt(
        fernet_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key


def decrypt_fernet_key_with_rsa(encrypted_key, private_key_pem):
    private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
    decrypted_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key


def cleanup_expired_messages():
    with app.app_context():
        now = datetime.utcnow()
        expired_messages = Message.query.filter(
            db.func.UNIX_TIMESTAMP(Message.timestamp) + Message.lifespan < now.timestamp()
        ).all()

        for message in expired_messages:
            db.session.delete(message)
        db.session.commit()


def rotate_secret_key():
    app.config['SECRET_KEY'] = os.urandom(32)


scheduler = BackgroundScheduler()
scheduler.add_job(cleanup_expired_messages, 'interval', minutes=1)
scheduler.add_job(rotate_secret_key, 'interval', minutes=15)
scheduler.start()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.config['SECRET_KEY'] = os.urandom(32)
    try:
        app.run(host='0.0.0.0', port=5000)
    finally:
        scheduler.shutdown()
