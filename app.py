import os
import random
from datetime import datetime

from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
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


@app.route('/create', methods=['POST'])
@login_required
def create_link():
    """Create a shortened link and corresponding QR code."""
    original_url = request.form['original_url']
    slug = generate_words()

    # Ensure slug is unique; regenerate if collision occurs
    while Link.query.filter_by(slug=slug).first() is not None:
        slug = generate_words()

    short_url = url_for('redirect_link', slug=slug, _external=True)
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
    # Create database tables if they don't exist
    if not os.path.exists('qricklinks.db'):
        # SQLAlchemy operations need an application context
        with app.app_context():
            db.create_all()
    # Run the Flask development server
    app.run(debug=True)
