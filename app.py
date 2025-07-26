import os
import random
from datetime import datetime

from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from sqlalchemy import func
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode

# Initialize Flask app and database
app = Flask(__name__)
app.config['SECRET_KEY'] = 'change-this-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///qricklinks.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ----------------------------
# Database Models
# ----------------------------
class User(UserMixin, db.Model):
    """Stores registered users."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    links = db.relationship('Link', backref='owner', lazy=True)
    # Flag to determine if the user has administrative privileges
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password: str) -> None:
        """Hash and store the user's password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Verify a password against the stored hash."""
        return check_password_hash(self.password_hash, password)


class Link(db.Model):
    """Represents a shortened link with tracking information."""
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(64), unique=True, nullable=False)
    original_url = db.Column(db.String(2048), nullable=False)
    qr_filename = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    visit_count = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    visits = db.relationship('Visit', backref='link', lazy=True)


class Visit(db.Model):
    """Stores individual visit records for links."""
    id = db.Column(db.Integer, primary_key=True)
    link_id = db.Column(db.Integer, db.ForeignKey('link.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip = db.Column(db.String(100))
    referrer = db.Column(db.String(2048))


class Setting(db.Model):
    """Stores global application settings."""
    id = db.Column(db.Integer, primary_key=True)
    base_url = db.Column(db.String(512), default='http://localhost:5000')


@login_manager.user_loader
def load_user(user_id: str):
    """Flask-Login user loader callback."""
    return User.query.get(int(user_id))


# ----------------------------
# Utility functions
# ----------------------------
ADJECTIVES = [
    'silent', 'quick', 'bright', 'lazy', 'happy', 'brave', 'calm', 'eager',
    'fancy', 'gentle', 'jolly', 'kind', 'lucky', 'merry', 'nice', 'proud'
]
NOUNS = [
    'tiger', 'river', 'mountain', 'sky', 'ocean', 'forest', 'panda', 'lion',
    'eagle', 'whale', 'wolf', 'falcon', 'shark', 'koala', 'leopard', 'otter'
]


def generate_words() -> str:
    """Generate a random 'adjective.adjective.noun' slug."""
    first_adj = random.choice(ADJECTIVES)
    second_adj = random.choice(ADJECTIVES)
    noun = random.choice(NOUNS)
    return f"{first_adj}.{second_adj}.{noun}"


def create_qr_code(url: str, slug: str) -> str:
    """Generate QR code image and return filename."""
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    filename = f"{slug}.png"
    filepath = os.path.join('static', 'qr', filename)
    img.save(filepath)
    return filename


def get_settings() -> Setting:
    """Retrieve the single settings row, creating it if missing."""
    settings = Setting.query.first()
    if not settings:
        settings = Setting()
        db.session.add(settings)
        db.session.commit()
    return settings


def admin_required(f):
    """Decorator to restrict routes to admin users only."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function


# ----------------------------
# Routes
# ----------------------------
@app.route('/')
@login_required
def index():
    """Show dashboard with user's links."""
    links = Link.query.filter_by(owner=current_user).all()
    return render_template('dashboard.html', links=links)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid credentials')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """Log the current user out."""
    logout_user()
    return redirect(url_for('login'))


# ----------------------------
# Admin Routes
# ----------------------------

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page with fixed credentials."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, is_admin=True).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('admin_dashboard'))
        flash('Invalid admin credentials')
    return render_template('admin_login.html')


@app.route('/admin/logout')
@admin_required
def admin_logout():
    """Log out the admin user."""
    logout_user()
    return redirect(url_for('admin_login'))


@app.route('/admin')
@admin_required
def admin_dashboard():
    """Display site statistics for the admin."""
    user_count = User.query.filter_by(is_admin=False).count()
    link_count = Link.query.count()
    total_clicks = db.session.query(func.sum(Link.visit_count)).scalar() or 0
    settings = get_settings()
    return render_template('admin_dashboard.html', user_count=user_count,
                           link_count=link_count, total_clicks=total_clicks,
                           settings=settings)


@app.route('/admin/settings', methods=['GET', 'POST'])
@admin_required
def admin_settings():
    """Allow the admin to update global site settings."""
    settings = get_settings()
    if request.method == 'POST':
        settings.base_url = request.form['base_url']
        db.session.commit()
        flash('Settings updated')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_settings.html', settings=settings)


@app.route('/create', methods=['POST'])
@login_required
def create_link():
    """Create a shortened link and corresponding QR code."""
    original_url = request.form['original_url']
    slug = generate_words()

    # Ensure slug is unique; regenerate if collision occurs
    while Link.query.filter_by(slug=slug).first() is not None:
        slug = generate_words()

    # Build the short URL using the configured base URL
    base_url = get_settings().base_url.rstrip('/')
    short_url = f"{base_url}/{slug}"
    qr_filename = create_qr_code(short_url, slug)

    link = Link(
        slug=slug,
        original_url=original_url,
        qr_filename=qr_filename,
        owner=current_user
    )
    db.session.add(link)
    db.session.commit()
    flash('Short link created!')
    return redirect(url_for('index'))


@app.route('/qr/<filename>')
def serve_qr(filename):
    """Serve generated QR code images."""
    return send_from_directory(os.path.join('static', 'qr'), filename)


@app.route('/<slug>')
def redirect_link(slug: str):
    """Redirect to the original URL and record visit information."""
    link = Link.query.filter_by(slug=slug).first_or_404()
    link.visit_count += 1

    visit = Visit(
        link=link,
        ip=request.remote_addr,
        referrer=request.referrer
    )
    db.session.add(visit)
    db.session.commit()
    return redirect(link.original_url)


if __name__ == '__main__':
    # Always run database related setup inside the application context
    with app.app_context():
        # Create tables if they do not yet exist
        db.create_all()

        # ------------------------------------------------------------------
        # Schema migration helper
        # ------------------------------------------------------------------
        # When the application is updated, the existing SQLite database may
        # lack newer columns. The following check ensures the "is_admin" column
        # exists on the user table and adds it on the fly if missing. This
        # avoids manual migrations for small schema changes.
        columns = [row[1] for row in db.session.execute("PRAGMA table_info(user)").fetchall()]
        if 'is_admin' not in columns:
            db.session.execute("ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT 0")
            db.session.commit()

        # Ensure a settings row is present
        get_settings()

        # Create the administrator account if it doesn't already exist
        if not User.query.filter_by(username='philadmin', is_admin=True).first():
            admin = User(username='philadmin', is_admin=True)
            admin.set_password('Admin12345')
            db.session.add(admin)
            db.session.commit()

    # Run the Flask development server
    app.run(debug=True)
