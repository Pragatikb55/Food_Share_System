# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import csv
import io

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-this')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://postgres:password@localhost/food_waste_db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'donor', 'ngo'
    organization = db.Column(db.String(200))
    phone = db.Column(db.String(20))
    address = db.Column(db.Text)
    city = db.Column(db.String(100))
    state = db.Column(db.String(50))
    zip_code = db.Column(db.String(20))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    verified = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    food_listings = db.relationship('FoodListing', backref='donor', lazy=True, cascade='all, delete-orphan')
    claims = db.relationship('Claim', backref='receiver', lazy=True, cascade='all, delete-orphan')
    notifications = db.relationship('Notification', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def get_role_display(self):
        role_names = {
            'donor': 'Food Donor',
            'ngo': 'NGO/Organization'
        }
        return role_names.get(self.role, self.role)
    
    @property
    def unread_notifications(self):
        return Notification.query.filter_by(user_id=self.id, is_read=False).count()

class FoodListing(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    food_type = db.Column(db.String(50))  # cooked, packaged, raw
    quantity = db.Column(db.Integer, nullable=False)  # number of meals
    location = db.Column(db.String(300), nullable=False)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    pickup_address = db.Column(db.Text)
    pickup_start = db.Column(db.DateTime, nullable=False)
    pickup_end = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='available')  # available, claimed, picked_up, expired, cancelled
    allergens = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Foreign Keys
    donor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationships
    claims = db.relationship('Claim', backref='food_listing', lazy=True, cascade='all, delete-orphan')

class Claim(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    food_listing_id = db.Column(db.Integer, db.ForeignKey('food_listing.id'), nullable=False)
    ngo_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, confirmed, picked_up, cancelled
    pickup_time = db.Column(db.DateTime)
    notes = db.Column(db.Text)
    people_served = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text)
    notification_type = db.Column(db.String(50))  # new_listing, claim_update, system
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rating = db.Column(db.Integer, nullable=False)  # 1-5
    comment = db.Column(db.Text)
    from_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    to_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    claim_id = db.Column(db.Integer, db.ForeignKey('claim.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper functions
def calculate_distance(lat1, lon1, lat2, lon2):
    """Calculate distance between two coordinates in kilometers"""
    from math import radians, sin, cos, sqrt, atan2
    
    R = 6371  # Earth's radius in kilometers
    
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1-a))
    
    return R * c

def format_datetime(value, format='%b %d, %Y %I:%M %p'):
    """Format datetime for templates"""
    if value is None:
        return ""
    return value.strftime(format)

# Add filter to Jinja2
app.jinja_env.filters['datetime'] = format_datetime

# =============== ROUTES ===============

@app.route('/')
def index():
    """Home page"""
    total_donations = FoodListing.query.count()
    total_meals = db.session.query(db.func.sum(FoodListing.quantity)).scalar() or 0
    total_ngos = User.query.filter_by(role='ngo').count()
    total_donors = User.query.filter_by(role='donor').count()
    
    return render_template('index.html', 
                         total_donations=total_donations,
                         total_meals=total_meals,
                         total_ngos=total_ngos,
                         total_donors=total_donors)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password) and user.is_active:
            login_user(user, remember=remember)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            flash('Login successful!', 'success')
            
            # Redirect based on role
            if user.role == 'donor':
                return redirect(url_for('donor_dashboard'))
            elif user.role == 'ngo':
                return redirect(url_for('ngo_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role')
        organization = request.form.get('organization', '')
        phone = request.form.get('phone', '')
        
        # Validation
        errors = []
        
        if password != confirm_password:
            errors.append('Passwords do not match')
        
        if User.query.filter_by(email=email).first():
            errors.append('Email already registered')
        
        if User.query.filter_by(username=username).first():
            errors.append('Username already taken')
        
        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('register.html')
        
        # Create new user
        user = User(
            username=username,
            email=email,
            role=role,
            organization=organization if role == 'ngo' else None,
            phone=phone
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    """Logout user"""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """General dashboard - redirects to role-specific dashboard"""
    if current_user.role == 'donor':
        return redirect(url_for('donor_dashboard'))
    elif current_user.role == 'ngo':
        return redirect(url_for('ngo_dashboard'))
    else:
        flash('Invalid user role', 'danger')
        return redirect(url_for('index'))

# =============== DONOR ROUTES ===============
@app.route('/donor/dashboard')
@login_required
def donor_dashboard():
    """Donor dashboard"""
    if current_user.role != 'donor':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get donor's listings
    listings = FoodListing.query.filter_by(donor_id=current_user.id)\
        .order_by(FoodListing.created_at.desc()).limit(5).all()
    
    # Get donor's claims (from their listings)
    claims = Claim.query.join(FoodListing)\
        .filter(FoodListing.donor_id == current_user.id)\
        .order_by(Claim.created_at.desc()).limit(5).all()
    
    # Calculate stats
    total_listings = FoodListing.query.filter_by(donor_id=current_user.id).count()
    available_listings = FoodListing.query.filter_by(donor_id=current_user.id, status='available').count()
    claimed_listings = FoodListing.query.filter_by(donor_id=current_user.id, status='claimed').count()
    total_meals_result = db.session.query(db.func.sum(FoodListing.quantity))\
        .filter(FoodListing.donor_id == current_user.id, FoodListing.status == 'picked_up').first()
    total_meals = total_meals_result[0] or 0 if total_meals_result else 0
    
    return render_template('donor/donor_dashboard.html',
                         listings=listings,
                         claims=claims,
                         total_listings=total_listings,
                         available_listings=available_listings,
                         claimed_listings=claimed_listings,
                         total_meals=total_meals)

@app.route('/create_listing', methods=['GET', 'POST'])
@login_required
def create_listing():
    """Create new food listing"""
    if current_user.role != 'donor':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Parse form data
        title = request.form.get('title')
        description = request.form.get('description')
        food_type = request.form.get('food_type')
        quantity = int(request.form.get('quantity'))
        location = request.form.get('location')
        pickup_address = request.form.get('pickup_address')
        pickup_start_str = request.form.get('pickup_start')
        pickup_end_str = request.form.get('pickup_end')
        allergens = request.form.get('allergens', '')
        
        # Convert datetime strings
        pickup_start = datetime.fromisoformat(pickup_start_str.replace('Z', '+00:00'))
        pickup_end = datetime.fromisoformat(pickup_end_str.replace('Z', '+00:00'))
        
        # Create new listing
        listing = FoodListing(
            title=title,
            description=description,
            food_type=food_type,
            quantity=quantity,
            location=location,
            pickup_address=pickup_address,
            pickup_start=pickup_start,
            pickup_end=pickup_end,
            allergens=allergens,
            donor_id=current_user.id
        )
        
        db.session.add(listing)
        db.session.commit()
        
        # Create notification for nearby NGOs
        nearby_ngos = User.query.filter_by(role='ngo').all()
        for ngo in nearby_ngos:
            notification = Notification(
                user_id=ngo.id,
                title='New Food Available!',
                message=f'{title} ({quantity} meals) is available near you.',
                notification_type='new_listing'
            )
            db.session.add(notification)
        
        db.session.commit()
        
        flash('Food listing created successfully!', 'success')
        return redirect(url_for('donor_dashboard'))
    
    # Set default pickup times (now and 2 hours from now)
    now = datetime.utcnow()
    default_start = now.strftime('%Y-%m-%dT%H:%M')
    default_end = (now + timedelta(hours=2)).strftime('%Y-%m-%dT%H:%M')
    
    return render_template('donor/create_listing.html',
                         default_start=default_start,
                         default_end=default_end)

@app.route('/my_listings')
@login_required
def my_listings():
    """View donor's listings"""
    if current_user.role != 'donor':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    listings = FoodListing.query.filter_by(donor_id=current_user.id)\
        .order_by(FoodListing.created_at.desc()).all()
    
    return render_template('donor/my_listings.html', listings=listings)

@app.route('/listing/<int:listing_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_listing(listing_id):
    """Edit food listing"""
    if current_user.role != 'donor':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    listing = FoodListing.query.get_or_404(listing_id)
    
    if listing.donor_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('my_listings'))
    
    if listing.status != 'available':
        flash('Only available listings can be edited', 'warning')
        return redirect(url_for('my_listings'))
    
    if request.method == 'POST':
        listing.title = request.form.get('title')
        listing.quantity = int(request.form.get('quantity'))
        pickup_end_str = request.form.get('pickup_end')
        listing.pickup_end = datetime.fromisoformat(pickup_end_str.replace('Z', '+00:00'))
        
        db.session.commit()
        flash('Listing updated successfully!', 'success')
        return redirect(url_for('my_listings'))
    
    return render_template('donor/edit_listing.html', listing=listing)

@app.route('/listing/<int:listing_id>/delete', methods=['POST'])
@login_required
def delete_listing(listing_id):
    if current_user.role != 'donor':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))

    listing = FoodListing.query.get_or_404(listing_id)

    if listing.donor_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('my_listings'))

    # Delete related claims first
    Claim.query.filter_by(food_listing_id=listing.id).delete()

    db.session.delete(listing)
    db.session.commit()

    flash('Food listing deleted successfully!', 'success')
    return redirect(url_for('donor_dashboard'))


@app.route('/listing/<int:listing_id>/view')
@login_required
def view_listing(listing_id):
    """View single listing"""
    listing = FoodListing.query.get_or_404(listing_id)
    
    if current_user.role == 'donor' and listing.donor_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('donor_dashboard'))
    
    return render_template('donor/view_listing.html', listing=listing)

# =============== NGO ROUTES ===============
@app.route('/ngo/dashboard')
@login_required
def ngo_dashboard():
    """NGO dashboard"""
    if current_user.role != 'ngo':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get available listings
    available_listings = FoodListing.query.filter_by(status='available')\
        .filter(FoodListing.pickup_end > datetime.utcnow())\
        .order_by(FoodListing.created_at.desc()).limit(3).all()
    
    # Get NGO's claims
    my_claims = Claim.query.filter_by(ngo_id=current_user.id)\
        .order_by(Claim.created_at.desc()).limit(5).all()
    
    # Calculate stats
    total_claims = Claim.query.filter_by(ngo_id=current_user.id).count()
    active_claims = Claim.query.filter_by(ngo_id=current_user.id)\
        .filter(Claim.status.in_(['pending', 'confirmed'])).count()
    
    # Calculate total meals claimed
    completed_claims = Claim.query.filter_by(ngo_id=current_user.id, status='picked_up')\
        .join(FoodListing).all()
    total_meals_claimed = sum(claim.food_listing.quantity for claim in completed_claims)
    
    return render_template('ngo/ngo_dashboard.html',
                         available_listings=available_listings,
                         my_claims=my_claims,
                         total_claims=total_claims,
                         active_claims=active_claims,
                         total_meals_claimed=total_meals_claimed)

@app.route('/available_food')
@login_required
def available_food():
    """View all available food"""
    if current_user.role != 'ngo':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    listings = FoodListing.query.filter_by(status='available')\
        .filter(FoodListing.pickup_end > datetime.utcnow())\
        .order_by(FoodListing.created_at.desc()).all()
    
    return render_template('ngo/available_food.html', 
                         listings=listings,
                         datetime=datetime)

@app.route('/claim/<int:listing_id>', methods=['POST'])
@login_required
def claim_food(listing_id):
    """Claim food listing"""
    if current_user.role != 'ngo':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    listing = FoodListing.query.get_or_404(listing_id)
    
    if listing.status != 'available':
        flash('This listing is no longer available', 'danger')
        return redirect(url_for('available_food'))
    
    # Check if already claimed by this NGO
    existing_claim = Claim.query.filter_by(
        food_listing_id=listing_id,
        ngo_id=current_user.id
    ).first()
    
    if existing_claim:
        flash('You have already claimed this listing', 'warning')
        return redirect(url_for('ngo_dashboard'))
    
    # Create claim
    claim = Claim(
        food_listing_id=listing_id,
        ngo_id=current_user.id,
        status='pending'
    )
    
    # Update listing status
    listing.status = 'claimed'
    
    # Create notification for donor
    notification = Notification(
        user_id=listing.donor_id,
        title='Food Claimed!',
        message=f'{current_user.organization or current_user.username} has claimed your listing: {listing.title}',
        notification_type='claim_update'
    )
    
    db.session.add(claim)
    db.session.add(notification)
    db.session.commit()
    
    flash('Food claimed successfully! Please contact the donor for pickup.', 'success')
    return redirect(url_for('ngo_dashboard'))

@app.route('/my_claims')
@login_required
def my_claims():
    """View NGO's claims"""
    if current_user.role != 'ngo':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    claims = Claim.query.filter_by(ngo_id=current_user.id)\
        .order_by(Claim.created_at.desc()).all()
    
    return render_template('ngo/my_claims.html', 
                         claims=claims,
                         datetime=datetime)

@app.route('/claim/<int:claim_id>/update_status', methods=['POST'])
@login_required
def update_claim_status(claim_id):
    """Update claim status"""
    if current_user.role != 'ngo':
        return jsonify({'success': False, 'error': 'Permission denied'}), 403
    
    claim = Claim.query.get_or_404(claim_id)
    
    if claim.ngo_id != current_user.id:
        return jsonify({'success': False, 'error': 'Permission denied'}), 403
    
    data = request.get_json()
    new_status = data.get('status')
    notes = data.get('notes', '')
    people_served = data.get('people_served')
    
    if new_status in ['confirmed', 'picked_up', 'cancelled']:
        claim.status = new_status
        claim.notes = notes
        
        if new_status == 'picked_up':
            claim.pickup_time = datetime.utcnow()
            claim.food_listing.status = 'picked_up'
            claim.people_served = people_served or claim.food_listing.quantity
            
            # Create notification for donor
            notification = Notification(
                user_id=claim.food_listing.donor_id,
                title='Food Picked Up!',
                message=f'{current_user.organization} has picked up {claim.food_listing.title}',
                notification_type='claim_update'
            )
            db.session.add(notification)
        elif new_status == 'cancelled':
            claim.food_listing.status = 'available'
        
        db.session.commit()
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'Invalid status'}), 400

# =============== API ENDPOINTS ===============
@app.route('/api/notifications')
@login_required
def get_notifications():
    """Get user notifications"""
    notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False)\
        .order_by(Notification.created_at.desc()).limit(10).all()
    
    return jsonify({
        'count': len(notifications),
        'notifications': [{
            'id': n.id,
            'title': n.title,
            'message': n.message,
            'created_at': n.created_at.isoformat()
        } for n in notifications]
    })

@app.route('/api/notifications/mark_read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    """Mark notification as read"""
    notification = Notification.query.get_or_404(notification_id)
    
    if notification.user_id != current_user.id:
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    notification.is_read = True
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/listings/<int:listing_id>', methods=['DELETE'])
@login_required
def delete_listing_api(listing_id):
    """Delete a food listing (API endpoint)"""
    listing = FoodListing.query.get_or_404(listing_id)
    
    # Check permission - only donor can delete their own listing
    if listing.donor_id != current_user.id:
        return jsonify({'success': False, 'error': 'Permission denied'}), 403
    
    if listing.status != 'available':
        return jsonify({'success': False, 'error': 'Only available listings can be deleted'}), 400
    
    # Delete associated claims
    Claim.query.filter_by(food_listing_id=listing_id).delete()
    
    db.session.delete(listing)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/stats/total_meals')
def get_total_meals():
    """Get total meals donated (public API)"""
    total_meals = db.session.query(db.func.sum(FoodListing.quantity)).scalar() or 0
    total_donations = FoodListing.query.count()
    
    return jsonify({
        'total_meals': total_meals,
        'total_donations': total_donations,
        'total_claims': Claim.query.count(),
        'completed_claims': Claim.query.filter_by(status='picked_up').count()
    })

@app.route('/api/listings/available')
@login_required
def get_available_listings():
    """Get available listings for map/API"""
    listings = FoodListing.query.filter_by(status='available')\
        .filter(FoodListing.pickup_end > datetime.utcnow())\
        .order_by(FoodListing.created_at.desc()).all()
    
    result = []
    for listing in listings:
        result.append({
            'id': listing.id,
            'title': listing.title,
            'description': listing.description,
            'food_type': listing.food_type,
            'quantity': listing.quantity,
            'location': listing.location,
            'pickup_address': listing.pickup_address,
            'pickup_start': listing.pickup_start.isoformat(),
            'pickup_end': listing.pickup_end.isoformat(),
            'allergens': listing.allergens,
            'donor': {
                'id': listing.donor.id,
                'organization': listing.donor.organization or listing.donor.username,
                'email': listing.donor.email,
                'phone': listing.donor.phone
            }
        })
    
    return jsonify({'listings': result})

# =============== ERROR HANDLERS ===============
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('403.html'), 403

# =============== HELPER PAGES ===============
@app.route('/about')
def about():
    """About page"""
    return render_template('about.html')

@app.route('/contact')
def contact():
    """Contact page"""
    return render_template('contact.html')

@app.route('/privacy')
def privacy():
    """Privacy policy page"""
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    """Terms of service page"""
    return render_template('terms.html')

@app.route('/food-safety')
def food_safety():
    """Food safety guidelines"""
    return render_template('food_safety.html')

# =============== UTILITY FUNCTIONS ===============
def cleanup_expired_listings():
    """Mark expired listings as expired (run periodically)"""
    expired_listings = FoodListing.query.filter(
        FoodListing.status == 'available',
        FoodListing.pickup_end < datetime.utcnow()
    ).all()
    
    for listing in expired_listings:
        listing.status = 'expired'
    
    if expired_listings:
        db.session.commit()
        print(f"Marked {len(expired_listings)} listings as expired")

# =============== INITIALIZATION ===============
"""Initialize database and create admin user"""
db_initialized = False

@app.before_request
def init_db():
    global db_initialized
    if not db_initialized:
        db.create_all()
        db_initialized = True
    cleanup_expired_listings()

# =============== MAIN ===============
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)