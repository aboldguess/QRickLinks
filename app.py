import os
import random
from datetime import datetime, timedelta

from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    request,
    flash,
    send_from_directory,
    abort,
    send_file,
)
from urllib.parse import urlparse, quote
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from sqlalchemy import func, text  # text() allows execution of raw SQL strings
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import qrcode
from qrcode.image.styledpil import StyledPilImage
from qrcode.image.styles.moduledrawers import (
    SquareModuleDrawer,
    RoundedModuleDrawer,
    CircleModuleDrawer,
)
from qrcode.image.svg import SvgPathImage
from qrcode.image.styles.moduledrawers import svg as svg_drawers
import io
from qrcode.image.styles.colormasks import SolidFillColorMask
from PIL import ImageColor

# Initialize Flask app and database
app = Flask(__name__)
# Use a secret key from the environment if available so deployments can set
# their own value. A hard-coded default keeps development setups simple.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-this-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///qricklinks.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Number of extra premium actions granted to new/free accounts each month
FREEBIES_PER_MONTH = 3

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
    # Subscription flag and usage counters for premium features
    is_premium = db.Column(db.Boolean, default=False)
    usage_month = db.Column(db.String(7), default=lambda: datetime.utcnow().strftime('%Y-%m'))
    custom_colors_used = db.Column(db.Integer, default=0)
    advanced_styles_used = db.Column(db.Integer, default=0)
    logo_embedding_used = db.Column(db.Integer, default=0)
    analytics_used = db.Column(db.Integer, default=0)
    # Count how many times the user selected a custom slug this month
    custom_slugs_used = db.Column(db.Integer, default=0)
    # Count how many links the user created this month
    links_created = db.Column(db.Integer, default=0)
    # Track how many extra premium actions a free user may perform
    freebies_remaining = db.Column(db.Integer, default=FREEBIES_PER_MONTH)
    # Date when the freebies counter resets for the next period
    freebies_reset = db.Column(
        db.DateTime,
        default=lambda: (datetime.utcnow().replace(day=1) + timedelta(days=32)).replace(day=1),
    )
    # Basic billing information for subscription management. This keeps the
    # example self-contained and avoids integrating a real payment gateway.
    billing_name = db.Column(db.String(120))
    billing_card_last4 = db.Column(db.String(4))
    billing_expiry = db.Column(db.String(7))  # Stored as MM/YYYY
    subscription_renewal = db.Column(db.DateTime)
    # Reference to the user's current subscription tier. This is null when
    # the database is first migrated and users will be assigned the free tier
    # automatically on login or registration.
    tier_id = db.Column(db.Integer, db.ForeignKey('subscription_tier.id'))
    tier = db.relationship('SubscriptionTier')

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
    # Base62 short code used as an alternative to the human readable slug
    short_code = db.Column(db.String(10), unique=True, nullable=False)
    original_url = db.Column(db.String(2048), nullable=False)
    qr_filename = db.Column(db.String(128), nullable=False)
    # Store the customisation options used to generate the current QR code
    fill_color = db.Column(db.String(7), default="#000000")
    back_color = db.Column(db.String(7), default="#FFFFFF")
    box_size = db.Column(db.Integer, default=10)
    border = db.Column(db.Integer, default=4)
    pattern = db.Column(db.String(10), default="square")
    error_correction = db.Column(db.String(1), default="M")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    visit_count = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    visits = db.relationship('Visit', backref='link', lazy=True)

    @property
    def short_url(self) -> str:
        """Return the public short URL for this link."""
        # Retrieve the base URL from the settings table and strip any trailing
        # slash so concatenation is predictable.
        base_url = get_settings().base_url.rstrip('/')
        # Combine base URL and slug to form the full short URL
        return f"{base_url}/{self.slug}"

    @property
    def code_url(self) -> str:
        """Return the short URL using the base62 code."""
        base_url = get_settings().base_url.rstrip('/')
        return f"{base_url}/{self.short_code}"

    @property
    def thumbnail_url(self) -> str:
        """Return a screenshot URL for the destination page."""
        # The thum.io service takes the target URL as part of the path.
        # Encoding the entire URL with ``quote_plus`` breaks this format
        # by escaping characters like ``:`` and ``/``. We only escape
        # characters that would terminate the path such as ``?`` or ``#``
        # while leaving the scheme and slashes intact so the request
        # uses ``https://image.thum.io/get/width/300/https://example.com``.
        encoded = quote(self.original_url, safe=':/')
        return f"https://image.thum.io/get/width/300/{encoded}"


class Visit(db.Model):
    """Stores individual visit records for links."""
    id = db.Column(db.Integer, primary_key=True)
    link_id = db.Column(db.Integer, db.ForeignKey('link.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip = db.Column(db.String(100))
    # Optional MAC address resolved from the ARP cache for local clients
    mac = db.Column(db.String(100))
    referrer = db.Column(db.String(2048))


class Setting(db.Model):
    """Stores global application settings."""
    id = db.Column(db.Integer, primary_key=True)
    base_url = db.Column(db.String(512), default='http://localhost:5000')
    # Monthly limit for how many links free users can create
    links_limit = db.Column(db.Integer, default=20)
    custom_colors_limit = db.Column(db.Integer, default=5)
    advanced_styles_limit = db.Column(db.Integer, default=5)
    logo_embedding_limit = db.Column(db.Integer, default=1)
    analytics_limit = db.Column(db.Integer, default=100)
    # Number of custom slugs free users may choose each month
    custom_slugs_limit = db.Column(db.Integer, default=5)


class Payment(db.Model):
    """Records a subscription payment made by a user."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship back to the paying user
    user = db.relationship('User', backref='payments', lazy=True)

class SubscriptionTier(db.Model):
    """Defines a pricing tier with feature limits."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    # Cost of the subscription when billed monthly
    monthly_price = db.Column(db.Float, default=0.0)
    # Cost of the subscription when billed yearly
    yearly_price = db.Column(db.Float, default=0.0)
    highlight_text = db.Column(db.String(100))
    # Monthly link creation quota per tier
    links_limit = db.Column(db.Integer)
    links_unlimited = db.Column(db.Boolean, default=False)
    custom_colors_limit = db.Column(db.Integer)
    custom_colors_unlimited = db.Column(db.Boolean, default=False)
    advanced_styles_limit = db.Column(db.Integer)
    advanced_styles_unlimited = db.Column(db.Boolean, default=False)
    logo_embedding_limit = db.Column(db.Integer)
    logo_embedding_unlimited = db.Column(db.Boolean, default=False)
    analytics_limit = db.Column(db.Integer)
    analytics_unlimited = db.Column(db.Boolean, default=False)
    # Monthly quota for user-specified slugs
    custom_slugs_limit = db.Column(db.Integer)
    custom_slugs_unlimited = db.Column(db.Boolean, default=False)
    archived = db.Column(db.Boolean, default=False)

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


def generate_short_code(length: int = 6) -> str:
    """Return a random base62 string of the given length."""
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return "".join(random.choice(alphabet) for _ in range(length))


def normalize_url(url: str) -> str:
    """Ensure the provided URL includes a scheme."""
    # urlparse will interpret "google.com" as a path with an empty scheme.
    # To keep the client-side form flexible (it now accepts plain text),
    # prepend "https://" when the scheme is missing so redirects work.
    if not urlparse(url).scheme:
        return f"https://{url}"
    return url


def get_mac_address(ip: str) -> str | None:
    """Lookup the MAC address for an IP from the OS ARP cache."""
    try:
        output = os.popen(f"arp -n {ip}").read()
        for line in output.splitlines():
            if ip in line:
                parts = line.split()
                for part in parts:
                    if part.count(":") == 5:
                        return part
    except Exception:
        pass
    return None


def create_qr_code(
    url: str,
    slug: str,
    *,
    fill_color: str = "#000000",
    back_color: str = "#FFFFFF",
    box_size: int = 10,
    border: int = 4,
    error_correction: str = "M",
    pattern: str = "square",
    logo_filename: str | None = None,
) -> str:
    """Generate a customised QR code image and return its filename."""

    # Map error correction levels from user-friendly letters to qrcode constants
    ec_map = {
        "L": qrcode.constants.ERROR_CORRECT_L,
        "M": qrcode.constants.ERROR_CORRECT_M,
        "Q": qrcode.constants.ERROR_CORRECT_Q,
        "H": qrcode.constants.ERROR_CORRECT_H,
    }
    error_correction_level = ec_map.get(error_correction.upper(), qrcode.constants.ERROR_CORRECT_M)

    # When embedding a logo the qrcode library requires the highest
    # error correction level (H).  Adjust automatically so users do not
    # encounter cryptic errors when uploading a logo with a lower level
    # selected in the form.
    if logo_filename and error_correction_level != qrcode.constants.ERROR_CORRECT_H:
        error_correction_level = qrcode.constants.ERROR_CORRECT_H

    # Select the module drawer style used to render QR modules
    drawers = {
        "square": SquareModuleDrawer(),
        # A radius ratio of 1 draws each module as a circle, producing a
        # noticeably different look from the default square modules.
        # RoundedModuleDrawer considers neighbouring modules when applying the
        # curvature so connected modules blend together cleanly.
        "rounded": RoundedModuleDrawer(radius_ratio=1),
        "circle": CircleModuleDrawer(),
    }
    # Fallback to a square pattern if an unknown option is provided
    drawer = drawers.get(pattern, SquareModuleDrawer())

    # Build the QRCode object with the provided customisation options
    qr = qrcode.QRCode(
        box_size=box_size,
        border=border,
        error_correction=error_correction_level,
    )
    qr.add_data(url)
    qr.make(fit=True)

    # Convert colour strings to RGB tuples that PIL understands. Using RGB
    # avoids an alpha channel, which would otherwise make the QR code drawing
    # treat the background as transparent and produce a solid square.
    try:
        if isinstance(fill_color, str):
            fill_color = ImageColor.getcolor(fill_color, "RGB")
        if isinstance(back_color, str):
            back_color = ImageColor.getcolor(back_color, "RGB")
    except ValueError:
        # Invalid colour code supplied; notify the user and abort the
        # QR generation process gracefully.
        flash("Invalid colour value provided")
        return None

    # Use a color mask so foreground/background colours can be customised
    color_mask = SolidFillColorMask(back_color=back_color, front_color=fill_color)

    embedded_path = None
    if logo_filename:
        # Place a user uploaded logo in the centre of the QR code
        embedded_path = os.path.join("static", "logos", logo_filename)

    img = qr.make_image(
        image_factory=StyledPilImage,
        color_mask=color_mask,
        module_drawer=drawer,
        embedded_image_path=embedded_path,
    )

    filename = f"{slug}.png"
    filepath = os.path.join("static", "qr", filename)
    img.save(filepath)
    return filename


def generate_qr_svg(link: 'Link') -> io.BytesIO:
    """Return an SVG QR code for the given link."""

    # Recreate the short URL that the existing PNG encodes
    base_url = get_settings().base_url.rstrip('/')
    short_url = f"{base_url}/{link.short_code}"

    # Map error correction letters to qrcode constants
    ec_map = {
        "L": qrcode.constants.ERROR_CORRECT_L,
        "M": qrcode.constants.ERROR_CORRECT_M,
        "Q": qrcode.constants.ERROR_CORRECT_Q,
        "H": qrcode.constants.ERROR_CORRECT_H,
    }
    level = ec_map.get(link.error_correction.upper(), qrcode.constants.ERROR_CORRECT_M)

    qr = qrcode.QRCode(
        box_size=link.box_size,
        border=link.border,
        error_correction=level,
    )
    qr.add_data(short_url)
    qr.make(fit=True)

    # Use SVG-specific module drawers; fall back to squares if pattern unknown
    svg_map = {
        'square': svg_drawers.SvgPathSquareDrawer(),
        'rounded': svg_drawers.SvgPathCircleDrawer(),
        'circle': svg_drawers.SvgPathCircleDrawer(),
    }
    drawer = svg_map.get(link.pattern, svg_drawers.SvgPathSquareDrawer())

    img = qr.make_image(image_factory=SvgPathImage, module_drawer=drawer)

    # Apply colours so the SVG matches the customised PNG version
    img.QR_PATH_STYLE['fill'] = link.fill_color
    img.background = link.back_color

    buffer = io.BytesIO()
    img.save(buffer)
    buffer.seek(0)
    return buffer


def get_settings() -> Setting:
    """Retrieve the single settings row, creating it if missing."""
    settings = Setting.query.first()
    if not settings:
        settings = Setting()
        db.session.add(settings)
        db.session.commit()
    return settings

# Map premium features to their Setting quota and User usage fields
FEATURE_LIMIT_FIELDS = {
    'links': ('links_limit', 'links_created'),
    'custom_colors': ('custom_colors_limit', 'custom_colors_used'),
    'advanced_styles': ('advanced_styles_limit', 'advanced_styles_used'),
    'logo_embedding': ('logo_embedding_limit', 'logo_embedding_used'),
    'analytics': ('analytics_limit', 'analytics_used'),
    'custom_slugs': ('custom_slugs_limit', 'custom_slugs_used'),
}


def reset_usage_if_needed(user: User) -> None:
    """Reset counters when a new month begins."""
    current_month = datetime.utcnow().strftime('%Y-%m')
    if user.usage_month != current_month:
        user.usage_month = current_month
        user.custom_colors_used = 0
        user.advanced_styles_used = 0
        user.logo_embedding_used = 0
        user.analytics_used = 0
        user.custom_slugs_used = 0
        # Reset the monthly link creation count
        user.links_created = 0
        db.session.commit()

    # Freebies reset independently of the monthly counters. When the stored
    # reset date is reached or passed, refresh the freebies allotment and set
    # the next renewal for the first of the following month.
    if user.freebies_reset and datetime.utcnow() >= user.freebies_reset:
        user.freebies_remaining = FREEBIES_PER_MONTH
        next_reset = user.freebies_reset.replace(day=1) + timedelta(days=32)
        user.freebies_reset = next_reset.replace(day=1)
        db.session.commit()


def can_use_feature(user: User, feature: str) -> bool:
    """Return True if the user has remaining quota for the feature."""
    reset_usage_if_needed(user)
    tier = user.tier or SubscriptionTier.query.filter_by(name='Free').first()
    if getattr(tier, f'{feature}_unlimited'):
        return True
    limit = getattr(tier, f'{feature}_limit') or 0
    used_field = FEATURE_LIMIT_FIELDS[feature][1]
    used = getattr(user, used_field)
    if used < limit:
        return True
    return user.freebies_remaining > 0


def check_feature_usage(user: User, feature: str) -> bool:
    """Return True and record usage if quota permits."""
    if not can_use_feature(user, feature):
        return False

    tier = user.tier or SubscriptionTier.query.filter_by(name='Free').first()
    if not getattr(tier, f'{feature}_unlimited'):
        used_field = FEATURE_LIMIT_FIELDS[feature][1]
        limit = getattr(tier, f'{feature}_limit') or 0
        used = getattr(user, used_field)
        if used >= limit and user.freebies_remaining > 0:
            user.freebies_remaining -= 1
        else:
            setattr(user, used_field, used + 1)
    db.session.commit()
    return True


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
    # Refresh monthly usage counters so the freebies display is accurate
    reset_usage_if_needed(current_user)
    links = Link.query.filter_by(owner=current_user).all()
    # Determine if the user still has link creation quota available so the
    # template can disable the form when exhausted.
    can_create = can_use_feature(current_user, 'links')
    return render_template('dashboard.html', links=links, can_create=can_create)


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
        # Automatically place new accounts on the free tier so quota checks use
        # the correct limits from the start.
        user.tier = SubscriptionTier.query.filter_by(name='Free').first()
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
            # Existing accounts created before tiers were introduced won't
            # have a tier assigned. Default them to the free tier so usage
            # limits work correctly.
            if user.tier is None:
                user.tier = SubscriptionTier.query.filter_by(name='Free').first()
                db.session.commit()
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


@app.route('/pricing')
def pricing():
    """Display subscription options pulled from the database."""
    tiers = (
        SubscriptionTier.query.filter_by(archived=False)
        .order_by(SubscriptionTier.id)
        .all()
    )
    features = [
        'links',
        'custom_colors',
        'advanced_styles',
        'logo_embedding',
        'analytics',
        'custom_slugs',
    ]
    # Pass the built-in ``getattr`` so Jinja can dynamically access
    # tier limits/unlimited flags in the template.  Without this the
    # templates raise an UndefinedError for ``getattr``.
    return render_template('pricing.html', tiers=tiers, features=features,
                           getattr=getattr)


@app.route('/checkout/<int:tier_id>', methods=['GET', 'POST'])
@login_required
def checkout(tier_id: int):
    """Placeholder checkout page for purchasing a subscription tier."""
    # Look up the selected tier or return 404 if it doesn't exist
    tier = SubscriptionTier.query.get_or_404(tier_id)
    if request.method == 'POST':
        # Perform a fake transaction. The real payment logic will be added
        # later using Stripe.
        # Assign the selected tier to the user. Payment handling will be
        # integrated later so this simply records the choice.
        current_user.tier = tier
        payment = Payment(user=current_user, amount=tier.monthly_price)
        db.session.add(payment)
        db.session.commit()
        flash(f'Subscribed to {tier.name}!')
        return redirect(url_for('index'))
    return render_template('checkout.html', tier=tier)


@app.route('/subscribe', methods=['GET', 'POST'])
@login_required
def subscribe():
    """Upgrade the current user to a premium subscription."""
    if request.method == 'POST':
        # The early access program grants the Pro tier for free
        pro_tier = SubscriptionTier.query.filter_by(name='Pro').first()
        current_user.tier = pro_tier
        payment = Payment(user=current_user, amount=0.0)
        db.session.add(payment)
        db.session.commit()
        flash('Subscription activated!')
        return redirect(url_for('index'))
    return render_template('subscribe.html')


@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    """Display subscription status, quotas and billing details."""
    # Refresh monthly counters so quota calculations are correct
    reset_usage_if_needed(current_user)
    # Build a mapping of feature -> remaining quota text using the user's tier
    quotas: dict[str, str] = {}
    tier = current_user.tier or SubscriptionTier.query.filter_by(name='Free').first()
    for feat in FEATURE_LIMIT_FIELDS:
        used_field = FEATURE_LIMIT_FIELDS[feat][1]
        if getattr(tier, f'{feat}_unlimited'):
            quotas[feat] = 'Unlimited'
        else:
            limit = getattr(tier, f'{feat}_limit') or 0
            used = getattr(current_user, used_field)
            quotas[feat] = f"{max(limit - used, 0)} of {limit}"

    # When the form is submitted update the stored billing details
    if request.method == 'POST':
        current_user.billing_name = request.form.get('billing_name')
        current_user.billing_card_last4 = request.form.get('billing_card_last4')
        current_user.billing_expiry = request.form.get('billing_expiry')
        db.session.commit()
        flash('Billing information updated')
        return redirect(url_for('account'))

    return render_template('account.html', quotas=quotas)


@app.route('/cancel_subscription', methods=['POST'])
@login_required
def cancel_subscription():
    """Downgrade the current user to the free plan."""
    # Move the user back to the free tier and clear any renewal date
    current_user.tier = SubscriptionTier.query.filter_by(name='Free').first()
    current_user.subscription_renewal = None
    db.session.commit()
    flash('Subscription cancelled')
    return redirect(url_for('account'))


@app.route('/settings')
@login_required
def user_settings():
    """Legacy route that redirects to the account page."""
    return redirect(url_for('account'))


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
        settings.links_limit = int(request.form['links_limit'])
        settings.custom_colors_limit = int(request.form['custom_colors_limit'])
        settings.advanced_styles_limit = int(request.form['advanced_styles_limit'])
        settings.logo_embedding_limit = int(request.form['logo_embedding_limit'])
        settings.analytics_limit = int(request.form['analytics_limit'])
        settings.custom_slugs_limit = int(request.form['custom_slugs_limit'])
        db.session.commit()
        flash('Settings updated')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_settings.html', settings=settings)


@app.route('/admin/users')
@admin_required
def admin_users():
    """Display all non-admin users and their usage details."""
    users = User.query.filter_by(is_admin=False).all()
    user_rows = []
    for user in users:
        link_count = Link.query.filter_by(owner=user).count()
        total_clicks = (
            db.session.query(func.sum(Link.visit_count))
            .filter_by(user_id=user.id)
            .scalar()
            or 0
        )
        user_rows.append(
            {
                "user": user,
                "link_count": link_count,
                "total_clicks": total_clicks,
                "payments": user.payments,
            }
        )
    return render_template("admin_users.html", users=user_rows)

@app.route('/admin/tiers', methods=['GET', 'POST'])
@admin_required
def admin_tiers():
    """Create and edit subscription tiers."""
    features = [
        'links',
        'custom_colors',
        'advanced_styles',
        'logo_embedding',
        'analytics',
        'custom_slugs',
    ]
    tiers = SubscriptionTier.query.order_by(SubscriptionTier.id).all()
    if request.method == 'POST':
        new_name = request.form.get('new_tier_name')
        if new_name:
            # Create a new tier using the provided name
            db.session.add(SubscriptionTier(name=new_name))
            db.session.commit()
            flash('Tier added')
            return redirect(url_for('admin_tiers'))
        # Update existing tiers with submitted values
        for tier in tiers:
            # Update subscription pricing for both billing intervals
            tier.monthly_price = float(
                request.form.get(f'{tier.id}_monthly_price', tier.monthly_price or 0)
            )
            tier.yearly_price = float(
                request.form.get(f'{tier.id}_yearly_price', tier.yearly_price or 0)
            )
            tier.highlight_text = request.form.get(f'{tier.id}_highlight_text', '')
            for feat in features:
                limit_val = request.form.get(f'{tier.id}_{feat}_limit')
                unlimited = request.form.get(f'{tier.id}_{feat}_unlimited')
                setattr(tier, f'{feat}_unlimited', bool(unlimited))
                if unlimited:
                    setattr(tier, f'{feat}_limit', None)
                else:
                    setattr(tier, f'{feat}_limit', int(limit_val) if limit_val else 0)
        db.session.commit()
        flash('Tiers updated')
        return redirect(url_for('admin_tiers'))
    # Provide ``getattr`` to the template so feature limits can be
    # resolved dynamically for each tier column.
    return render_template('admin_tiers.html', tiers=tiers,
                           features=features, getattr=getattr)


@app.route('/admin/tiers/delete/<int:tier_id>')
@admin_required
def delete_tier(tier_id: int):
    """Permanently remove a subscription tier."""
    tier = SubscriptionTier.query.get_or_404(tier_id)
    db.session.delete(tier)
    db.session.commit()
    flash('Tier deleted')
    return redirect(url_for('admin_tiers'))


@app.route('/admin/tiers/archive/<int:tier_id>')
@admin_required
def archive_tier(tier_id: int):
    """Toggle the archived state of a tier."""
    tier = SubscriptionTier.query.get_or_404(tier_id)
    tier.archived = not tier.archived
    db.session.commit()
    flash('Tier archived' if tier.archived else 'Tier restored')
    return redirect(url_for('admin_tiers'))

@app.route('/create', methods=['POST'])
@login_required
def create_link():
    """Create a shortened link and corresponding QR code."""
    # Normalise the submitted URL so missing schemes default to https://
    original_url = normalize_url(request.form['original_url'])
    # Enforce the monthly link creation limit for free users
    if not check_feature_usage(current_user, 'links'):
        flash('Link creation quota exceeded')
        return redirect(url_for('index'))
    # Use the submitted slug when provided. Falling back to a randomly
    # generated "adjective.adjective.noun" slug keeps behaviour unchanged
    # for users who leave the slug field blank.
    submitted_slug = request.form.get("slug", "").strip()
    slug = submitted_slug or generate_words()
    # Only deduct custom slug quota when a slug is explicitly provided.
    # Random slugs generated by the server remain free to encourage usage.
    if submitted_slug and not check_feature_usage(current_user, 'custom_slugs'):
        flash('Custom slug quota exceeded')
        return redirect(url_for('index'))
    short_code = generate_short_code()

    # Customisation options supplied by the user or using defaults.
    # When the simplified creation form omits these fields the defaults are
    # applied so a valid QR code is still generated.
    fill_color = request.form.get("fill_color", "#000000")
    back_color = request.form.get("back_color", "#FFFFFF")
    box_size = int(request.form.get("box_size", 10))
    border = int(request.form.get("border", 4))
    pattern = request.form.get("pattern", "square")
    error_correction = request.form.get("error_correction", "M")
    logo_file = request.files.get("logo")
    logo_filename = None

    if logo_file and logo_file.filename and not check_feature_usage(current_user, 'logo_embedding'):
        flash('Logo embedding quota exceeded')
        return redirect(url_for('index'))

    # Free tier limits for premium features
    if (fill_color != "#000000" or back_color != "#FFFFFF") and not check_feature_usage(current_user, 'custom_colors'):
        flash('Custom colours quota exceeded')
        return redirect(url_for('index'))
    if (
        box_size != 10
        or border != 4
        or pattern != 'square'
        or error_correction != 'M'
    ) and not check_feature_usage(current_user, 'advanced_styles'):
        flash('Advanced styling quota exceeded')
        return redirect(url_for('index'))
    if logo_file and logo_file.filename and not check_feature_usage(current_user, 'logo_embedding'):
        flash('Logo embedding quota exceeded')
        return redirect(url_for('index'))

    # Ensure slugs and codes are unique. If the requested slug already exists
    # a new random slug is generated so link creation always succeeds.
    while Link.query.filter_by(slug=slug).first() is not None:
        slug = generate_words()
    while Link.query.filter_by(short_code=short_code).first() is not None:
        short_code = generate_short_code()

    # Build the URL embedded in the QR code using the generated short code
    # rather than the human readable slug to keep the QR target minimal.
    base_url = get_settings().base_url.rstrip('/')
    short_url = f"{base_url}/{short_code}"

    # Save uploaded logo file if present
    if logo_file and logo_file.filename:
        logo_filename = f"{slug}_{secure_filename(logo_file.filename)}"
        logo_path = os.path.join("static", "logos", logo_filename)
        logo_file.save(logo_path)

    # Generate the QR code using the selected customisation options
    qr_filename = create_qr_code(
        short_url,
        slug,
        fill_color=fill_color,
        back_color=back_color,
        box_size=box_size,
        border=border,
        error_correction=error_correction,
        pattern=pattern,
        logo_filename=logo_filename,
    )
    # Abort link creation if the QR code could not be generated
    if qr_filename is None:
        return redirect(url_for('index'))

    link = Link(
        slug=slug,
        short_code=short_code,
        original_url=original_url,
        qr_filename=qr_filename,
        # Persist customisation options so the user can refine them later
        fill_color=fill_color,
        back_color=back_color,
        box_size=box_size,
        border=border,
        pattern=pattern,
        error_correction=error_correction,
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


@app.route('/download/<filename>/<fmt>')
@login_required
def download_qr(filename: str, fmt: str):
    """Provide a QR code file in the requested format."""

    # Look up the link so ownership and customisation details are available
    link = Link.query.filter_by(qr_filename=filename).first_or_404()
    if link.owner != current_user:
        abort(403)

    if fmt == 'png':
        # Serve the existing PNG image from disk
        return send_from_directory(
            os.path.join('static', 'qr'), filename, as_attachment=True
        )
    if fmt == 'svg':
        # Generate an SVG on the fly using the stored options
        svg_bytes = generate_qr_svg(link)
        return send_file(
            svg_bytes,
            mimetype='image/svg+xml',
            as_attachment=True,
            download_name=f"{link.slug}.svg",
        )

    abort(404)


@app.route('/delete/<int:link_id>', methods=['POST'])
@login_required
def delete_link(link_id: int):
    """Remove a link and all its related records."""
    link = Link.query.get_or_404(link_id)
    if link.owner != current_user:
        abort(403)

    # Erase visit history so no orphan rows remain
    Visit.query.filter_by(link_id=link.id).delete()

    # Remove the QR code image file from disk if present
    qr_path = os.path.join('static', 'qr', link.qr_filename)
    if os.path.exists(qr_path):
        os.remove(qr_path)

    db.session.delete(link)
    db.session.commit()

    flash('Link deleted. All associated records were removed and this cannot be undone.')
    return redirect(url_for('index'))


@app.route('/customize/<int:link_id>', methods=['POST'])
@login_required
def customize_link(link_id: int):
    """Update the QR code for an existing link using new options."""
    link = Link.query.get_or_404(link_id)
    if link.owner != current_user:
        abort(403)

    # Perform quota checks for the various customisation options the user is
    # attempting to modify. Each option corresponds to a premium feature tier.
    # Only consume quota when the submitted value differs from what is already
    # stored for the link so repeated saves do not double count.
    if (
        link.fill_color != request.form.get('fill_color', link.fill_color) or
        link.back_color != request.form.get('back_color', link.back_color)
    ) and not check_feature_usage(current_user, 'custom_colors'):
        flash('Custom colours quota exceeded')
        return redirect(url_for('index'))
    if (
        link.box_size != int(request.form.get('box_size', link.box_size)) or
        link.border != int(request.form.get('border', link.border)) or
        link.pattern != request.form.get('pattern', link.pattern) or
        link.error_correction != request.form.get('error_correction', link.error_correction)
    ) and not check_feature_usage(current_user, 'advanced_styles'):
        flash('Advanced styling quota exceeded')
        return redirect(url_for('index'))

    # Extract customisation parameters from the submitted form
    fill_color = request.form.get("fill_color", "#000000")
    back_color = request.form.get("back_color", "#FFFFFF")
    box_size = int(request.form.get("box_size", 10))
    border = int(request.form.get("border", 4))
    pattern = request.form.get("pattern", "square")
    error_correction = request.form.get("error_correction", "M")
    logo_file = request.files.get("logo")
    logo_filename = None

    if logo_file and logo_file.filename:
        if not check_feature_usage(current_user, 'logo_embedding'):
            flash('Logo embedding quota exceeded')
            return redirect(url_for('index'))
        # Store the uploaded logo file under a predictable name
        logo_filename = f"{link.slug}_{secure_filename(logo_file.filename)}"
        logo_path = os.path.join("static", "logos", logo_filename)
        logo_file.save(logo_path)

    # Reconstruct the QR target URL using the existing short code so any
    # updated image continues to point to the minimal short link.
    base_url = get_settings().base_url.rstrip('/')
    short_url = f"{base_url}/{link.short_code}"

    # Regenerate the QR code image and update the filename field
    link.qr_filename = create_qr_code(
        short_url,
        link.slug,
        fill_color=fill_color,
        back_color=back_color,
        box_size=box_size,
        border=border,
        error_correction=error_correction,
        pattern=pattern,
        logo_filename=logo_filename,
    )
    # Abort update if QR generation failed
    if link.qr_filename is None:
        return redirect(url_for('index'))
    # Persist the updated customisation options
    link.fill_color = fill_color
    link.back_color = back_color
    link.box_size = box_size
    link.border = border
    link.pattern = pattern
    link.error_correction = error_correction
    db.session.commit()
    flash('QR code updated')
    return redirect(url_for('index'))


@app.route('/details/<int:link_id>')
@login_required
def link_details(link_id: int):
    """Display analytics and visit information for a single link."""
    link = Link.query.get_or_404(link_id)
    if link.owner != current_user:
        abort(403)
    # Determine whether analytics quota permits viewing the details.  Usage is
    # only recorded when access is granted.
    if not check_feature_usage(current_user, 'analytics'):
        return render_template('link_details.html', link=link, premium=False)

    # Retrieve all visits for this link ordered newest first
    visits = (
        Visit.query
        .filter_by(link_id=link.id)
        .order_by(Visit.timestamp.desc())
        .all()
    )

    # Collate unique visitors by their IP/MAC pair so we can count them and show
    # when each visitor accessed the link
    unique_map: dict[tuple[str | None, str | None], list[datetime]] = {}
    for v in visits:
        key = (v.ip, v.mac)
        unique_map.setdefault(key, []).append(v.timestamp)

    return render_template(
        'link_details.html',
        link=link,
        premium=True,
        total_clicks=link.visit_count,
        unique_count=len(unique_map),
        visit_map=unique_map,
    )


@app.route('/<slug>')
def redirect_link(slug: str):
    """Redirect to the original URL and record visit information."""
    # Accept either the human readable slug or the base62 short code
    link = Link.query.filter(
        (Link.slug == slug) | (Link.short_code == slug)
    ).first_or_404()
    link.visit_count += 1

    # Attempt to capture a MAC address for local visitors using the ARP cache
    mac = get_mac_address(request.remote_addr)

    visit = Visit(
        link=link,
        ip=request.remote_addr,
        mac=mac,
        referrer=request.referrer
    )
    db.session.add(visit)
    db.session.commit()
    return redirect(link.original_url)


def initialize_database() -> None:
    """Create database tables and default records."""
    with app.app_context():
        # Ensure tables exist before the server starts
        db.create_all()

        # ------------------------------------------------------------------
        # Schema migration helper
        # ------------------------------------------------------------------
        # When the application is updated, the existing SQLite database may
        # lack newer columns. The following check ensures the "is_admin" column
        # exists on the user table and adds it on the fly if missing. This
        # avoids manual migrations for small schema changes.
        columns = [row[1] for row in db.session.execute(text("PRAGMA table_info(user)")).fetchall()]
        if 'is_admin' not in columns:
            db.session.execute(text("ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT 0"))
            db.session.commit()
        # Paywall related columns
        user_map = {
            'is_premium': 'BOOLEAN DEFAULT 0',
            'usage_month': "VARCHAR(7) DEFAULT '{}'".format(datetime.utcnow().strftime('%Y-%m')),
            'custom_colors_used': 'INTEGER DEFAULT 0',
            'advanced_styles_used': 'INTEGER DEFAULT 0',
            'logo_embedding_used': 'INTEGER DEFAULT 0',
            'analytics_used': 'INTEGER DEFAULT 0',
            'custom_slugs_used': 'INTEGER DEFAULT 0',
            'links_created': 'INTEGER DEFAULT 0',
            'freebies_remaining': f'INTEGER DEFAULT {FREEBIES_PER_MONTH}',
            'freebies_reset': 'DATETIME',
            'billing_name': 'VARCHAR(120)',
            'billing_card_last4': 'VARCHAR(4)',
            'billing_expiry': 'VARCHAR(7)',
            'subscription_renewal': 'DATETIME',
            'tier_id': 'INTEGER',
        }
        added_user_cols = False
        for column, ddl in user_map.items():
            if column not in columns:
                db.session.execute(text(f"ALTER TABLE user ADD COLUMN {column} {ddl}"))
                added_user_cols = True

        if added_user_cols:
            db.session.commit()
            # Initialise freebies for existing users so everyone starts
            # with a full allocation once the new columns are added.
            next_reset = (datetime.utcnow().replace(day=1) + timedelta(days=32)).replace(day=1)
            User.query.update({
                User.freebies_remaining: FREEBIES_PER_MONTH,
                User.freebies_reset: next_reset,
                User.links_created: 0,
                User.custom_slugs_used: 0,
            })
            free_tier = SubscriptionTier.query.filter_by(name='Free').first()
            if free_tier:
                User.query.filter(User.tier_id.is_(None)).update({User.tier_id: free_tier.id})
            db.session.commit()

        # Retrieve column information for the link table so we can determine
        # which fields may need to be added. Existing installations may not have
        # all the customisation options that newer versions include.
        link_columns = [
            row[1] for row in db.session.execute(text("PRAGMA table_info(link)")).fetchall()
        ]

        visit_columns = [
            row[1] for row in db.session.execute(text("PRAGMA table_info(visit)")).fetchall()
        ]

        # ------------------------------------------------------------------
        # Customisation columns
        # ------------------------------------------------------------------
        # These columns store the user's QR code settings. They must exist
        # before we query using the Link model, otherwise SQLAlchemy will try to
        # select fields that SQLite doesn't know about.
        customization_map = {
            "fill_color": "VARCHAR(7) DEFAULT '#000000'",
            "back_color": "VARCHAR(7) DEFAULT '#FFFFFF'",
            "box_size": "INTEGER DEFAULT 10",
            "border": "INTEGER DEFAULT 4",
            "pattern": "VARCHAR(10) DEFAULT 'square'",
            "error_correction": "VARCHAR(1) DEFAULT 'M'",
        }

        added_custom_columns = False
        for column, ddl in customization_map.items():
            if column not in link_columns:
                db.session.execute(text(f"ALTER TABLE link ADD COLUMN {column} {ddl}"))
                added_custom_columns = True

        if added_custom_columns:
            db.session.commit()
            # Refresh column list so subsequent checks see the newly added ones
            link_columns = [
                row[1] for row in db.session.execute(text("PRAGMA table_info(link)")).fetchall()
            ]

        # ------------------------------------------------------------------
        # short_code column
        # ------------------------------------------------------------------
        # Add the short_code column after the customisation columns are in
        # place. This ensures Link.query works without hitting missing-column
        # errors when populating values for existing rows.
        if 'short_code' not in link_columns:
            # SQLite doesn't allow adding a UNIQUE column directly; add the
            # column first then create a unique index.
            db.session.execute(text("ALTER TABLE link ADD COLUMN short_code VARCHAR(10)"))
            db.session.commit()

            # Populate the new column for existing rows with generated codes
            for link in Link.query.all():
                code = generate_short_code()
                while Link.query.filter_by(short_code=code).first() is not None:
                    code = generate_short_code()
                link.short_code = code
            db.session.commit()

            # Enforce uniqueness using an index instead of a column constraint
            db.session.execute(
                text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_link_short_code ON link (short_code)"
                )
            )
            db.session.commit()

        # If the visit table lacks a MAC address column add it so future visits
        # can store hardware information when available.
        if 'mac' not in visit_columns:
            db.session.execute(text("ALTER TABLE visit ADD COLUMN mac VARCHAR(100)"))
            db.session.commit()

        # Settings table columns for paywall quotas
        setting_columns = [row[1] for row in db.session.execute(text("PRAGMA table_info(setting)")).fetchall()]
        setting_map = {
            'links_limit': 'INTEGER DEFAULT 20',
            'custom_colors_limit': 'INTEGER DEFAULT 5',
            'advanced_styles_limit': 'INTEGER DEFAULT 5',
            'logo_embedding_limit': 'INTEGER DEFAULT 1',
            'analytics_limit': 'INTEGER DEFAULT 100',
            'custom_slugs_limit': 'INTEGER DEFAULT 5',
        }
        added_setting_cols = False
        for column, ddl in setting_map.items():
            if column not in setting_columns:
                db.session.execute(text(f"ALTER TABLE setting ADD COLUMN {column} {ddl}"))
                added_setting_cols = True

        if added_setting_cols:
            db.session.commit()

        # Subscription tier pricing columns for monthly and yearly costs. Older
        # databases only store a single price so add the new fields if needed.
        tier_columns = [
            row[1]
            for row in db.session.execute(
                text("PRAGMA table_info(subscription_tier)")
            ).fetchall()
        ]
        tier_map = {
            'monthly_price': 'FLOAT DEFAULT 0.0',
            'yearly_price': 'FLOAT DEFAULT 0.0',
            'links_limit': 'INTEGER',
            'links_unlimited': 'BOOLEAN DEFAULT 0',
            'custom_slugs_limit': 'INTEGER',
            'custom_slugs_unlimited': 'BOOLEAN DEFAULT 0',
        }
        added_tier_cols = False
        for column, ddl in tier_map.items():
            if column not in tier_columns:
                db.session.execute(
                    text(f"ALTER TABLE subscription_tier ADD COLUMN {column} {ddl}")
                )
                added_tier_cols = True

        if added_tier_cols:
            db.session.commit()

        # Ensure a settings row is present
        get_settings()

        # Create the administrator account if it doesn't already exist
        if not User.query.filter_by(username='philadmin', is_admin=True).first():
            admin = User(username='philadmin', is_admin=True)
            admin.set_password('Admin12345')
            db.session.add(admin)
            db.session.commit()

        # Create some default subscription tiers if none exist.  The free tier
        # costs nothing while the paid tiers include monthly and yearly options
        # that will be displayed on the pricing page.
        if SubscriptionTier.query.count() == 0:
            free_settings = get_settings()
            db.session.add_all([
                SubscriptionTier(
                    name='Free',
                    links_limit=free_settings.links_limit,
                    custom_colors_limit=free_settings.custom_colors_limit,
                    advanced_styles_limit=free_settings.advanced_styles_limit,
                    logo_embedding_limit=free_settings.logo_embedding_limit,
                    analytics_limit=free_settings.analytics_limit,
                    custom_slugs_limit=free_settings.custom_slugs_limit,
                ),
                SubscriptionTier(name='Basic', monthly_price=5.0, yearly_price=50.0, links_unlimited=True, custom_colors_unlimited=True, advanced_styles_unlimited=True, logo_embedding_unlimited=True, analytics_unlimited=True, custom_slugs_unlimited=True),
                SubscriptionTier(name='Pro', monthly_price=10.0, yearly_price=100.0, links_unlimited=True, custom_colors_unlimited=True, advanced_styles_unlimited=True, logo_embedding_unlimited=True, analytics_unlimited=True, custom_slugs_unlimited=True),
            ])
            db.session.commit()


if __name__ == '__main__':
    # Prepare the database and default records before starting
    initialize_database()
    # Run the Flask development server
    app.run(debug=True)
