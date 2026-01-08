"""
Flask application for Quotation Management System
"""
import os
import csv
import io
import logging
import re
import secrets
import string
from datetime import datetime, timedelta
from decimal import Decimal
from functools import wraps

# Load environment variables FIRST - before any other imports that might use them
from dotenv import load_dotenv

# Get base directory paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# For cPanel: Try to load .env from multiple locations in order of priority
env_paths = [
    os.getenv('ENV_FILE'),  # Explicitly set path (highest priority)
    os.path.join(BASE_DIR, '.env'),  # quotation_backend directory
    os.path.join(os.path.dirname(BASE_DIR), '.env'),  # Project root
    os.path.join(os.path.dirname(os.path.dirname(BASE_DIR)), 'public_html', '.env'),  # public_html (cPanel)
    os.path.join(os.path.expanduser('~'), '.env'),  # Home directory
]

# Load .env from first available location (only once)
env_loaded = False
for env_path in env_paths:
    if env_path and os.path.exists(env_path):
        load_dotenv(env_path, override=True)
        env_loaded = True
        break

# If no .env found in expected locations, try default location
if not env_loaded:
    load_dotenv()

# Now import Flask and other dependencies after .env is loaded
from flask import Flask, request, jsonify, make_response, send_from_directory, session
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash
from database import configure_database, init_database, test_connection, db
from models import (
    User, Item, Temp, Quotation, QuotationItem, 
    GstRule, Settings, Log
)
from schemas import (
    ItemCreateSchema, ItemUpdateSchema,
    QuotationCreateSchema, LogCreateSchema, GstRuleCreateSchema,
    SettingsUpdateSchema
)

# Frontend directory path
# In development, frontend is in project root
FRONTEND_DIR = os.getenv('FRONTEND_DIR')
if not FRONTEND_DIR:
    # Development mode: frontend is in project root (parent of quotation_backend)
    FRONTEND_DIR = os.path.join(os.path.dirname(BASE_DIR), 'frontend')

# Initialize Flask app with static folder configuration
app = Flask(__name__, 
            static_folder=FRONTEND_DIR,
            static_url_path='',
            template_folder=FRONTEND_DIR)

@app.route("/ping")
def ping():
    return "pong"


application = app

# Production mode detection (before using IS_PRODUCTION)
# Set FLASK_ENV=production or ENVIRONMENT=production to enable production mode
# In cPanel/Passenger, __name__ != '__main__', so we detect production mode
_IS_PRODUCTION_ENV = (
    os.getenv('FLASK_ENV', '').lower() == 'production' or
    os.getenv('ENVIRONMENT', '').lower() == 'production' or
    os.getenv('FLASK_DEBUG', '').lower() == 'false'
)

# Force production mode if running under WSGI (cPanel/Passenger)
if __name__ != '__main__':
    app.debug = False
    IS_PRODUCTION = True
else:
    IS_PRODUCTION = _IS_PRODUCTION_ENV or not app.debug

# Session Configuration
# SECRET_KEY will be validated after .env is loaded (see below)
# Session timeout: 8 hours (28800 seconds) - adjust as needed
# For higher security, use 30 minutes (1800 seconds) or 1 hour (3600 seconds)
SESSION_TIMEOUT_SECONDS = int(os.getenv('SESSION_TIMEOUT_SECONDS', 28800))  # Default: 8 hours
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=SESSION_TIMEOUT_SECONDS)

# Rate Limiting Configuration
# Flask-Limiter uses in-memory storage by default (suitable for single-server deployments)
# For multi-server deployments, use Redis: storage_uri="redis://localhost:6379"
RATE_LIMIT_STORAGE_URI = os.getenv('RATE_LIMIT_STORAGE_URI', 'memory://')
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[],  # No global limits by default
    storage_uri=RATE_LIMIT_STORAGE_URI,
    strategy="fixed-window"  # or "moving-window" for smoother rate limiting
)

# Rate limit configuration (configurable via environment variables)
# Format: "count per period" (e.g., "5 per 15 minutes")
LOGIN_RATE_LIMIT = os.getenv('LOGIN_RATE_LIMIT', '5 per 15 minutes')
API_RATE_LIMIT = os.getenv('API_RATE_LIMIT', '100 per minute')  # General API rate limit

# Enable CORS for API routes
# Set ALLOWED_ORIGINS in .env (comma-separated, e.g., https://quotation.purplehuetechnosoft.com)
allowed_origins = os.getenv('ALLOWED_ORIGINS', '*' if not IS_PRODUCTION else '')

# Parse and validate origins
if allowed_origins and allowed_origins != '*':
    # Parse comma-separated origins and validate format
    valid_origins = [o.strip() for o in allowed_origins.split(',') 
                     if o.strip() and (o.strip().startswith('http://') or o.strip().startswith('https://'))]
    
    if valid_origins:
        CORS(app, resources={r"/api/*": {"origins": valid_origins}})
        if IS_PRODUCTION:
            logging.info(f"CORS configured: {', '.join(valid_origins)}")
    elif IS_PRODUCTION:
        raise ValueError("ALLOWED_ORIGINS must be set in production (e.g., https://quotation.purplehuetechnosoft.com)")
    else:
        CORS(app, resources={r"/api/*": {"origins": "*"}})
        logging.warning("CORS: Invalid origins, using wildcard (*) - Development only")
elif IS_PRODUCTION:
    raise ValueError("ALLOWED_ORIGINS must be set in production (e.g., https://quotation.purplehuetechnosoft.com)")
else:
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    logging.warning("CORS: Allowing all origins (*) - Development only")

# Session Configuration - Validate SECRET_KEY after .env is loaded
# Set a secret key for session management (required for Flask sessions)
# In production, this MUST be set via environment variable or .env file
SECRET_KEY = os.getenv('SECRET_KEY')

# Validate SECRET_KEY
if not SECRET_KEY:
    if IS_PRODUCTION:
        raise ValueError(
            "SECURITY ERROR: SECRET_KEY environment variable is required in production.\n"
            "Please set it in your .env file:\n"
            "1. Generate a strong key: python -c \"import secrets; print(secrets.token_urlsafe(32))\"\n"
            "2. Add to .env: SECRET_KEY=your-generated-key-here\n"
            "3. Ensure .env file has proper permissions (chmod 600 .env)"
        )
    else:
        # Development fallback (not secure, but allows development)
        SECRET_KEY = 'dev-secret-key-change-in-production-' + str(os.urandom(24))
        logging.warning("Using auto-generated SECRET_KEY for development. Set SECRET_KEY in production!")

# Validate SECRET_KEY strength in production
if IS_PRODUCTION and SECRET_KEY:
    if len(SECRET_KEY) < 32:
        logging.warning(
            f"SECRET_KEY is too short ({len(SECRET_KEY)} chars). "
            "Recommendation: Use at least 32 characters for production security. "
            "Generate with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
        )
    # Check if it's the default dev key (shouldn't be used in production)
    if SECRET_KEY.startswith('dev-secret-key'):
        raise ValueError(
            "SECURITY ERROR: Development SECRET_KEY detected in production mode. "
            "Please set a strong SECRET_KEY in your .env file."
        )

app.config['SECRET_KEY'] = SECRET_KEY

# Session Cookie Configuration for production
# Ensure cookies work properly with HTTPS in production
if IS_PRODUCTION:
    app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
else:
    app.config['SESSION_COOKIE_SECURE'] = False  # Allow HTTP in development
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Configure database - .env is already loaded above
# Database configuration must happen after .env is loaded
try:
    configure_database(app)
    if IS_PRODUCTION:
        logging.info("Database configuration successful.")
    else:
        print("Database configuration successful.")
except Exception as e:
    import traceback
    error_msg = f"ERROR: Database configuration failed: {e}"
    if IS_PRODUCTION:
        logging.error(error_msg, exc_info=True)
        logging.error("Database environment variables (DB_HOST, DB_USER, DB_PASSWORD, DB_NAME) must be set in .env file.")
        # In production, fail fast if database is not configured
        raise ValueError(
            "Database configuration failed. Please ensure DB_HOST, DB_USER, DB_PASSWORD, and DB_NAME "
            "are set in your .env file. Check application logs for details."
        )
    else:
        print(error_msg)
        print("App will start but database features may not work.")
        print("Make sure environment variables are set in .env file.")
        traceback.print_exc()
        # In development, allow app to start with minimal config
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        try:
            db.init_app(app)
        except Exception:
            pass


# Configuration
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'svg'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# IS_PRODUCTION is already defined above (before SECRET_KEY configuration)


# ============================================================================
# Helper Functions
# ============================================================================

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_secure_password(length=16):
    """
    Generate a secure random password.
    
    Args:
        length: Length of the password (default: 16)
    
    Returns:
        A secure random password string
    """
    # Use a mix of uppercase, lowercase, digits, and special characters
    # Exclude ambiguous characters like 0, O, I, l
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    # Remove ambiguous characters
    alphabet = alphabet.replace('0', '').replace('O', '').replace('o', '')
    alphabet = alphabet.replace('1', '').replace('I', '').replace('l', '')
    
    # Generate secure random password
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    
    # Ensure password has at least one of each type
    if not any(c.islower() for c in password):
        password = password[:-1] + secrets.choice(string.ascii_lowercase)
    if not any(c.isupper() for c in password):
        password = password[:-1] + secrets.choice(string.ascii_uppercase)
    if not any(c.isdigit() for c in password):
        password = password[:-1] + secrets.choice(string.digits)
    
    return password


def jsonp_response(data, callback=None):
    """
    Create JSONP response for cross-origin requests
    User preference: Use JSONP instead of CORS
    """
    import json
    if callback:
        # Use json.dumps to ensure proper encoding and avoid truncation
        json_str = json.dumps(data, ensure_ascii=False)
        response = make_response(f"{callback}({json_str})")
        response.headers['Content-Type'] = 'application/javascript; charset=utf-8'
        return response
    return jsonify(data)


def get_jsonp_callback():
    """Get JSONP callback from request"""
    try:
        return request.args.get('callback')
    except RuntimeError:
        # Request context not available (e.g., in error handlers during app init)
        return None


def handle_error(error_message, status_code=400, callback=None, detailed_error=None):
    """
    Handle errors with JSONP support.
    In production, returns generic error messages to clients while logging detailed errors server-side.
    
    Args:
        error_message: Generic error message to return to client
        status_code: HTTP status code
        callback: JSONP callback function name
        detailed_error: Detailed error for server-side logging (optional)
    """
    # Log detailed error server-side if provided
    if detailed_error:
        if IS_PRODUCTION:
            # In production, always log detailed errors server-side
            logging.error(f"Error: {error_message} | Details: {detailed_error}")
        else:
            # In development, log for debugging
            logging.error(f"Error details: {detailed_error}")
    
    # In production, sanitize error messages to prevent information leakage
    if IS_PRODUCTION and status_code >= 500:
        # For server errors in production, use generic message
        error_message = 'An internal server error occurred. Please try again later.'
    
    error_data = {
        'success': False,
        'error': error_message,
        'message': error_message  # Also include as 'message' for consistency
    }
    response = jsonp_response(error_data, callback)
    # Ensure Content-Type is set correctly
    if not callback:
        # Regular JSON response
        response.headers['Content-Type'] = 'application/json'
    # For JSONP, Content-Type is already set to 'application/javascript' in jsonp_response
    return response, status_code


def handle_success(data=None, message='Success', callback=None):
    """Handle success responses with JSONP support"""
    response_data = {
        'success': True,
        'message': message
    }
    if data is not None:
        response_data['data'] = data
    return jsonp_response(response_data, callback)


# ============================================================================
# Authentication & Authorization Middleware
# ============================================================================

def require_auth(f):
    """
    Decorator to require authentication for an endpoint.
    Checks Flask session first, falls back to headers/query params for backward compatibility.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        callback = get_jsonp_callback()
        
        # Check Flask session first (preferred method)
        user_id = session.get('user_id')
        user_email = session.get('user_email')
        
        # Fallback to headers or query params for backward compatibility
        if not user_email:
            user_email = request.headers.get('X-User-Email') or request.args.get('email')
        
        if not user_email:
            return handle_error('Authentication required. Please log in.', 401, callback)
        
        # Verify user exists and is active
        try:
            # If we have user_id from session, use it for faster lookup
            if user_id:
                user = User.query.get(user_id)
            else:
                user = User.query.filter_by(email=user_email.lower()).first()
            
            if not user:
                # Clear invalid session
                session.clear()
                return handle_error('User not found', 401, callback)
            
            if not user.is_active:
                # Clear session for inactive user
                session.clear()
                return handle_error('Account is inactive', 403, callback)
            
            # Verify session email matches user email (security check)
            if user_id and user.email.lower() != user_email.lower():
                session.clear()
                return handle_error('Session validation failed', 401, callback)
            
            # Attach user to request context for use in route handler
            request.current_user = user
            return f(*args, **kwargs)
        except Exception as e:
            # Clear session on error
            session.clear()
            return handle_error('Authentication failed. Please try again.', 500, callback, detailed_error=str(e))
    
    return decorated_function


def require_role(*allowed_roles):
    """
    Decorator to require specific role(s) for an endpoint.
    Must be used after @require_auth decorator.
    
    Usage:
        @app.route('/api/admin-only')
        @require_auth
        @require_role('Owner', 'Admin')
        def admin_endpoint():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            callback = get_jsonp_callback()
            
            # Get user from request context (set by require_auth)
            user = getattr(request, 'current_user', None)
            if not user:
                return handle_error('Authentication required', 401, callback)
            
            # Check if user has required role
            if user.role not in allowed_roles:
                return handle_error(
                    f'Access denied. Required role(s): {", ".join(allowed_roles)}', 
                    403, 
                    callback
                )
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# ============================================================================
# Authentication Endpoints
# ============================================================================

@app.route('/api/login', methods=['POST'])
def login():
    """
    User login endpoint with role-based authentication.
    """
    callback = get_jsonp_callback()
    
    try:
        # Handle form data or JSON
        if request.is_json:
            data = request.get_json()
        else:
            data = {
                'email': request.form.get('email'),
                'password': request.form.get('password')
            }
        
        # Validate input
        if not data.get('email') or not data.get('password'):
            return handle_error('Email and password are required', 400, callback)
        
        # Normalize email
        email = data['email'].strip().lower()
        password = data['password']
        
        # Check database connection
        try:
            db.session.execute(db.text('SELECT 1'))
        except Exception as db_error:
            return handle_error('Database connection failed. Please check server configuration.', 500, callback)
        
        # Find user in database
        try:
            user = User.query.filter_by(email=email).first()
        except Exception as query_error:
            return handle_error('Database query failed. Please try again.', 500, callback)
        
        if not user:
            # Check if any users exist in database
            try:
                user_count = User.query.count()
                if user_count == 0:
                    return handle_error(
                        'No users found in database. Please run the insert_users.sql script to add users. '
                        'Default test users: owner@gmail.com (password: owner123), admin@gmail.com (password: admin123), etc.',
                        401, 
                        callback
                    )
            except Exception as count_error:
                # If count fails, just return generic error
                pass
            
            return handle_error('Invalid email or password', 401, callback)
        
        # Verify password
        try:
            password_valid = user.check_password(password)
        except Exception as pwd_error:
            return handle_error('Password verification failed. Please try again.', 500, callback)
        
        if not password_valid:
            return handle_error('Invalid email or password', 401, callback)
        
        # Check if account is active
        if not user.is_active:
            return handle_error('Account is inactive. Please contact administrator.', 403, callback)
        
        # Create Flask session
        session.permanent = True
        session['user_id'] = user.id
        session['user_email'] = user.email
        session['user_role'] = user.role
        
        # Role-based redirect mapping
        role_redirects = {
            'Owner': '/owner.html',
            'Admin': '/admin.html',
            'Manager': '/manager.html',
            'Sales': '/employee.html',
            'Accountant': '/accountant.html',
            'Employee': '/employee.html'
        }
        
        redirect_url = role_redirects.get(user.role, '/index.html')
        
        # Create audit log entry
        try:
            log = Log(
                action='User Login',
                role=user.role,
                user=user.email.split('@')[0] if '@' in user.email else user.email,
                user_id=user.id,
                details=f'User {user.email} ({user.role}) logged in successfully'
            )
            db.session.add(log)
            db.session.commit()
        except Exception as log_error:
            # Log error but don't fail login
            db.session.rollback()
        
        # Prepare user data for frontend (exclude sensitive info)
        user_data = {
            'id': user.id,
            'email': user.email,
            'role': user.role,
            'name': user.name or '',
            'phone': user.phone or '',
            'is_active': user.is_active
        }
        
        return handle_success({
            'redirect': redirect_url,
            'user': user_data,
            'role': user.role,
            'message': f'Welcome, {user.name or user.email}!',
            'sessionTimeout': SESSION_TIMEOUT_SECONDS
        }, 'Login successful', callback)
        
    except Exception as e:
        db.session.rollback()
        return handle_error('Login failed. Please try again.', 500, callback, detailed_error=str(e))


@app.route('/api/logout', methods=['POST'])
def logout():
    """User logout endpoint"""
    callback = get_jsonp_callback()
    
    try:
        # Get user info from session before clearing it
        user_id = session.get('user_id')
        user_email = session.get('user_email')
        user_role = session.get('user_role')
        
        # Create logout log entry if session exists
        if user_id:
            try:
                user = User.query.get(user_id)
                if user:
                    log = Log(
                        action='User Logout',
                        role=user.role,
                        user=user.email.split('@')[0] if '@' in user.email else user.email,
                        user_id=user.id,
                        details=f'User {user.email} logged out'
                    )
                    db.session.add(log)
                    db.session.commit()
            except Exception as log_error:
                db.session.rollback()
        
        # Clear Flask session
        session.clear()
        
        return handle_success({
            'redirect': '/index.html'
        }, 'Logout successful', callback)
        
    except Exception as e:
        db.session.rollback()
        return handle_error('Logout failed. Please try again.', 500, callback, detailed_error=str(e))


@app.route('/api/generate-password-hash', methods=['POST'])
@limiter.limit('10 per minute')
def generate_password_hash_endpoint():
    """
    Generate password hash endpoint - returns Werkzeug-compatible scrypt hash
    
    This endpoint uses Werkzeug's generate_password_hash() directly, ensuring
    100% compatibility with the database. The hash format is:
    scrypt:32768:8:1$[salt]$[hash]
    
    Where salt and hash are properly encoded to match Werkzeug's format exactly.
    Rate limited to prevent abuse.
    """
    callback = get_jsonp_callback()
    
    try:
        # Handle JSON or form data
        if request.is_json:
            data = request.get_json()
        else:
            data = {
                'password': request.form.get('password')
            }
        
        # Validate input
        if not data.get('password'):
            return handle_error('Password is required', 400, callback)
        
        password = data['password']
        
        # Generate hash using Werkzeug directly (guaranteed correct format)
        # This ensures salt and hash encoding match exactly what Werkzeug produces
        password_hash = generate_password_hash(password)
        
        return handle_success({
            'password': password,
            'hash': password_hash
        }, 'Password hash generated successfully', callback)
        
    except Exception as e:
        return handle_error('Failed to generate password hash. Please try again.', 500, callback)


@app.route('/api/current-user', methods=['GET'])
def get_current_user():
    """Get current user information (for session validation)"""
    callback = get_jsonp_callback()
    
    try:
        # Get user email from query params or headers
        email = request.args.get('email') or request.headers.get('X-User-Email')
        
        if not email:
            return handle_error('Email parameter required', 400, callback)
        
        user = User.query.filter_by(email=email.lower()).first()
        
        if not user:
            return handle_error('User not found', 404, callback)
        
        if not user.is_active:
            return handle_error('Account is inactive', 403, callback)
        
        # Return user data (exclude sensitive info)
        user_data = {
            'id': user.id,
            'email': user.email,
            'role': user.role,
            'name': user.name or '',
            'phone': user.phone or '',
            'is_active': user.is_active
        }
        
        return handle_success({
            'user': user_data
        }, callback=callback)
        
    except Exception as e:
        return handle_error('Failed to get user information. Please try again.', 500, callback, detailed_error=str(e))


# ============================================================================
# Items/Products Endpoints
# ============================================================================

@app.route('/api/items', methods=['GET'])
def get_items():
    """Get all items"""
    callback = get_jsonp_callback()
    
    try:
        items = Item.query.order_by(Item.created_at.desc()).all()
        items_data = [item.to_dict() for item in items]
        return handle_success(items_data, callback=callback)
    except Exception as e:
        return handle_error('Failed to fetch items. Please try again.', 500, callback, detailed_error=str(e))


@app.route('/api/items', methods=['POST'])
@require_auth
def create_item():
    """Create a new item - requires authentication"""
    callback = get_jsonp_callback()
    
    try:
        data = request.get_json()
        schema = ItemCreateSchema()
        errors = schema.validate(data)
        if errors:
            return handle_error(f'Validation error: {errors}', 400, callback)
        
        # Check if product_id already exists
        existing = Item.query.filter_by(product_id=data['productId']).first()
        if existing:
            return handle_error('Product ID already exists', 409, callback)
        
        # Create new item
        price = Decimal(str(data['price']))
        gst = Decimal(str(data.get('gst', 0))) if data.get('gst') is not None else Decimal('0')
        total_price = Decimal(str(data.get('totalPrice', 0))) if data.get('totalPrice') is not None else (price + gst)
        
        item = Item(
            product_id=data['productId'],
            item_url=data.get('itemUrl'),
            product_name=data['productName'],
            type=data.get('type'),
            price=price,
            gst=gst,
            total_price=total_price,
            description=data.get('description'),
            added_by=data.get('addedBy')
        )
        
        db.session.add(item)
        db.session.commit()
        
        return handle_success(item.to_dict(), 'Item created successfully', callback)
        
    except Exception as e:
        db.session.rollback()
        error_msg = str(e)
        # Check for duplicate entry error
        if 'Duplicate entry' in error_msg or '1062' in error_msg:
            return handle_error(f'Product ID "{data.get("productId", "unknown")}" already exists. Please use a different Product ID.', 409, callback)
        return handle_error(f'Failed to create item: {error_msg}', 500, callback)


@app.route('/api/items/<product_id>', methods=['GET'])
def get_item(product_id):
    """Get a single item by product_id"""
    callback = get_jsonp_callback()
    
    try:
        item = Item.query.filter_by(product_id=product_id).first()
        if not item:
            return handle_error('Item not found', 404, callback)
        
        return handle_success(item.to_dict(), callback=callback)
    except Exception as e:
        return handle_error('Failed to fetch item. Please try again.', 500, callback, detailed_error=str(e))


@app.route('/api/items/<product_id>', methods=['PUT'])
@require_auth
def update_item(product_id):
    """Update an item - requires authentication"""
    callback = get_jsonp_callback()
    
    try:
        item = Item.query.filter_by(product_id=product_id).first()
        if not item:
            return handle_error('Item not found', 404, callback)
        
        data = request.get_json()
        schema = ItemUpdateSchema()
        errors = schema.validate(data)
        if errors:
            return handle_error(f'Validation error: {errors}', 400, callback)
        
        # Update fields
        if 'itemUrl' in data:
            item.item_url = data['itemUrl']
        if 'productName' in data:
            item.product_name = data['productName']
        if 'type' in data:
            item.type = data['type']
        if 'price' in data:
            item.price = Decimal(str(data['price']))
        if 'gst' in data and data['gst'] is not None:
            item.gst = Decimal(str(data['gst']))
        if 'totalPrice' in data and data['totalPrice'] is not None:
            item.total_price = Decimal(str(data['totalPrice']))
        elif 'price' in data or ('gst' in data and data['gst'] is not None):
            # Auto-calculate total_price if price or gst is updated
            item.total_price = item.price + item.gst
        if 'description' in data:
            item.description = data['description']
        
        db.session.commit()
        
        return handle_success(item.to_dict(), 'Item updated successfully', callback)
        
    except Exception as e:
        db.session.rollback()
        return handle_error('Failed to update item. Please try again.', 500, callback, detailed_error=str(e))


@app.route('/api/items/<product_id>', methods=['DELETE'])
@require_auth
@require_role('Owner', 'Admin', 'Manager')
def delete_item(product_id):
    """Delete an item - requires authentication and Manager+ role"""
    callback = get_jsonp_callback()
    
    try:
        item = Item.query.filter_by(product_id=product_id).first()
        if not item:
            return handle_error('Item not found', 404, callback)
        
        db.session.delete(item)
        db.session.commit()
        
        return handle_success(None, 'Item deleted successfully', callback)
        
    except Exception as e:
        db.session.rollback()
        return handle_error('Failed to delete item. Please try again.', 500, callback, detailed_error=str(e))


# ============================================================================
# Temp Table Endpoints (for storing edited prices/GST)
# ============================================================================

@app.route('/api/temp', methods=['POST'])
@require_auth
def create_or_update_temp():
    """Create or update a temp item - requires authentication"""
    callback = get_jsonp_callback()
    
    try:
        data = request.get_json()
        
        if not data or 'productId' not in data:
            return handle_error('Product ID is required', 400, callback)
        
        product_id = data['productId']
        
        # Check if temp item already exists
        temp_item = Temp.query.filter_by(product_id=product_id).first()
        
        if temp_item:
            # Update existing temp item
            if 'itemUrl' in data:
                temp_item.item_url = data['itemUrl']
            if 'productName' in data:
                temp_item.product_name = data['productName']
            if 'type' in data:
                temp_item.type = data['type']
            if 'price' in data:
                temp_item.price = Decimal(str(data['price']))
            if 'gst' in data and data['gst'] is not None:
                temp_item.gst = Decimal(str(data['gst']))
            if 'totalPrice' in data and data['totalPrice'] is not None:
                temp_item.total_price = Decimal(str(data['totalPrice']))
            elif 'price' in data or ('gst' in data and data['gst'] is not None):
                # Auto-calculate total_price if price or gst is updated
                temp_item.total_price = temp_item.price + temp_item.gst
            if 'description' in data:
                temp_item.description = data['description']
            if 'addedBy' in data:
                temp_item.added_by = data['addedBy']
        else:
            # Create new temp item
            price = Decimal(str(data.get('price', 0)))
            gst = Decimal(str(data.get('gst', 0))) if data.get('gst') is not None else Decimal('0')
            total_price = Decimal(str(data.get('totalPrice', 0))) if data.get('totalPrice') is not None else (price + gst)
            
            temp_item = Temp(
                product_id=product_id,
                item_url=data.get('itemUrl'),
                product_name=data.get('productName', ''),
                type=data.get('type'),
                price=price,
                gst=gst,
                total_price=total_price,
                description=data.get('description'),
                added_by=data.get('addedBy')
            )
            db.session.add(temp_item)
        
        db.session.commit()
        return handle_success(temp_item.to_dict(), 'Temp item saved successfully', callback)
        
    except Exception as e:
        db.session.rollback()
        return handle_error(f'Failed to save temp item: {str(e)}', 500, callback, detailed_error=str(e))


@app.route('/api/temp/<product_id>', methods=['PUT'])
@require_auth
def update_temp(product_id):
    """Update a temp item - requires authentication"""
    callback = get_jsonp_callback()
    
    try:
        temp_item = Temp.query.filter_by(product_id=product_id).first()
        if not temp_item:
            return handle_error('Temp item not found', 404, callback)
        
        data = request.get_json()
        
        # Update fields
        if 'itemUrl' in data:
            temp_item.item_url = data['itemUrl']
        if 'productName' in data:
            temp_item.product_name = data['productName']
        if 'type' in data:
            temp_item.type = data['type']
        if 'price' in data:
            temp_item.price = Decimal(str(data['price']))
        if 'gst' in data and data['gst'] is not None:
            temp_item.gst = Decimal(str(data['gst']))
        if 'totalPrice' in data and data['totalPrice'] is not None:
            temp_item.total_price = Decimal(str(data['totalPrice']))
        elif 'price' in data or ('gst' in data and data['gst'] is not None):
            # Auto-calculate total_price if price or gst is updated
            temp_item.total_price = temp_item.price + temp_item.gst
        if 'description' in data:
            temp_item.description = data['description']
        if 'addedBy' in data:
            temp_item.added_by = data['addedBy']
        
        db.session.commit()
        return handle_success(temp_item.to_dict(), 'Temp item updated successfully', callback)
        
    except Exception as e:
        db.session.rollback()
        return handle_error('Failed to update temp item. Please try again.', 500, callback, detailed_error=str(e))


@app.route('/api/temp', methods=['GET'])
def get_temp_items():
    """Get all temp items"""
    callback = get_jsonp_callback()
    
    try:
        temp_items = Temp.query.order_by(Temp.created_at.desc()).all()
        temp_items_data = [item.to_dict() for item in temp_items]
        return handle_success(temp_items_data, callback=callback)
    except Exception as e:
        return handle_error('Failed to fetch temp items. Please try again.', 500, callback, detailed_error=str(e))


# ============================================================================
# Quotations Endpoints
# ============================================================================

@app.route('/api/quotations', methods=['GET'])
def get_quotations():
    """Get all quotations"""
    callback = get_jsonp_callback()
    
    try:
        quotations = Quotation.query.order_by(Quotation.created_at.desc()).all()
        quotations_data = [q.to_dict() for q in quotations]
        return handle_success(quotations_data, callback=callback)
    except Exception as e:
        return handle_error('Failed to fetch quotations. Please try again.', 500, callback, detailed_error=str(e))


@app.route('/api/quotations', methods=['POST'])
@require_auth
def create_quotation():
    """Create a new quotation - requires authentication"""
    callback = get_jsonp_callback()
    
    try:
        data = request.get_json()
        schema = QuotationCreateSchema()
        errors = schema.validate(data)
        if errors:
            return handle_error(f'Validation error: {errors}', 400, callback)
        
        # Check if quotation_id already exists
        existing = Quotation.query.filter_by(quotation_id=data['quotationId']).first()
        if existing:
            return handle_error('Quotation ID already exists', 409, callback)
        
        # Normalise customer name: allow null/empty from API but store
        # an empty string in the DB (the column is non-nullable).
        customer_payload = data.get('customer') or {}
        raw_customer_name = customer_payload.get('name')
        customer_name_db = raw_customer_name or ''

        # Create quotation
        quotation = Quotation(
            quotation_id=data['quotationId'],
            date_created=data['dateCreated'],
            customer_name=customer_name_db,
            customer_phone=customer_payload['phone'],
            customer_email=customer_payload.get('email'),
            customer_address=customer_payload.get('address'),
            sub_total=Decimal(str(data['subTotal'])),
            discount_percent=Decimal(str(data['discountPercent'])),
            discount_amount=Decimal(str(data['discountAmount'])),
            total_gst_amount=Decimal(str(data['totalGstAmount'])),
            grand_total=Decimal(str(data['grandTotal'])),
            created_by=data.get('createdBy')
        )
        
        db.session.add(quotation)
        db.session.flush()  # Get quotation ID
        
        # Add quotation items
        for item_data in data['items']:
            quotation_item = QuotationItem(
                quotation_id=quotation.id,
                product_id=item_data['productId'],
                product_name=item_data['productName'],
                price=Decimal(str(item_data['price'])),
                quantity=item_data['quantity'],
                gst_rate=Decimal(str(item_data['gstRate']))
            )
            db.session.add(quotation_item)
        
        db.session.commit()
        
        return handle_success(quotation.to_dict(), 'Quotation created successfully', callback)
        
    except Exception as e:
        db.session.rollback()
        return handle_error('Failed to create quotation. Please try again.', 500, callback, detailed_error=str(e))


@app.route('/api/quotations/<quotation_id>', methods=['GET'])
def get_quotation(quotation_id):
    """Get a single quotation by quotation_id"""
    callback = get_jsonp_callback()
    
    try:
        quotation = Quotation.query.filter_by(quotation_id=quotation_id).first()
        if not quotation:
            return handle_error('Quotation not found', 404, callback)
        
        return handle_success(quotation.to_dict(), callback=callback)
    except Exception as e:
        return handle_error('Failed to fetch quotation. Please try again.', 500, callback, detailed_error=str(e))


@app.route('/api/quotations/<quotation_id>', methods=['DELETE'])
@require_auth
@require_role('Owner', 'Admin', 'Manager')
def delete_quotation(quotation_id):
    """Delete a quotation - requires authentication and Manager+ role"""
    callback = get_jsonp_callback()
    
    try:
        quotation = Quotation.query.filter_by(quotation_id=quotation_id).first()
        if not quotation:
            return handle_error('Quotation not found', 404, callback)
        
        db.session.delete(quotation)
        db.session.commit()
        
        return handle_success(None, 'Quotation deleted successfully', callback)
        
    except Exception as e:
        db.session.rollback()
        return handle_error('Failed to delete quotation. Please try again.', 500, callback, detailed_error=str(e))


# ============================================================================
# Logs/Audit Endpoints
# ============================================================================

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Get all logs"""
    callback = get_jsonp_callback()
    
    try:
        logs = Log.query.order_by(Log.timestamp.desc()).all()
        logs_data = [log.to_dict() for log in logs]
        return handle_success(logs_data, callback=callback)
    except Exception as e:
        return handle_error('Failed to fetch logs. Please try again.', 500, callback, detailed_error=str(e))


@app.route('/api/logs', methods=['POST'])
@require_auth
def create_log():
    """Create a new log entry - requires authentication"""
    callback = get_jsonp_callback()
    
    try:
        data = request.get_json()
        schema = LogCreateSchema()
        errors = schema.validate(data)
        if errors:
            return handle_error(f'Validation error: {errors}', 400, callback)
        
        log = Log(
            action=data['action'],
            role=data['role'],
            details=data.get('details'),
            user=data.get('user')
        )
        
        db.session.add(log)
        db.session.commit()
        
        return handle_success(log.to_dict(), 'Log created successfully', callback)
        
    except Exception as e:
        db.session.rollback()
        return handle_error('Failed to create log entry. Please try again.', 500, callback, detailed_error=str(e))


@app.route('/api/logs/<int:log_id>', methods=['DELETE'])
@require_auth
@require_role('Owner', 'Admin')
def delete_log(log_id):
    """Delete a log entry - requires authentication and Admin+ role"""
    callback = get_jsonp_callback()
    
    try:
        log = Log.query.get(log_id)
        if not log:
            return handle_error('Log not found', 404, callback)
        
        db.session.delete(log)
        db.session.commit()
        
        return handle_success(None, 'Log deleted successfully', callback)
        
    except Exception as e:
        db.session.rollback()
        return handle_error('Failed to delete log entry. Please try again.', 500, callback, detailed_error=str(e))


# ============================================================================
# GST Rules Endpoints
# ============================================================================

@app.route('/api/gst_rules', methods=['GET'])
def get_gst_rules():
    """Get all GST rules"""
    callback = get_jsonp_callback()
    
    try:
        rules = GstRule.query.order_by(GstRule.created_at.desc()).all()
        rules_data = [rule.to_dict() for rule in rules]
        return handle_success(rules_data, callback=callback)
    except Exception as e:
        return handle_error('Failed to fetch GST rules. Please try again.', 500, callback, detailed_error=str(e))


@app.route('/api/gst_rules', methods=['POST'])
@require_auth
@require_role('Owner', 'Admin', 'Manager')
def create_gst_rule():
    """Create a new GST rule - requires authentication and Manager+ role"""
    callback = get_jsonp_callback()
    
    try:
        data = request.get_json()
        schema = GstRuleCreateSchema()
        errors = schema.validate(data)
        if errors:
            return handle_error(f'Validation error: {errors}', 400, callback)
        
        # Check if rule already exists for this product
        existing = GstRule.query.filter_by(product_name=data['productName']).first()
        if existing:
            # Update existing rule
            existing.percent = Decimal(str(data['percent']))
            db.session.commit()
            return handle_success(existing.to_dict(), 'GST rule updated successfully', callback)
        
        # Create new rule
        rule = GstRule(
            product_name=data['productName'],
            percent=Decimal(str(data['percent']))
        )
        
        db.session.add(rule)
        db.session.commit()
        
        return handle_success(rule.to_dict(), 'GST rule created successfully', callback)
        
    except Exception as e:
        db.session.rollback()
        return handle_error('Failed to create GST rule. Please try again.', 500, callback, detailed_error=str(e))


@app.route('/api/gst_rules/<int:rule_id>', methods=['DELETE'])
@require_auth
@require_role('Owner', 'Admin', 'Manager')
def delete_gst_rule(rule_id):
    """Delete a GST rule - requires authentication and Manager+ role"""
    callback = get_jsonp_callback()
    
    try:
        rule = GstRule.query.get(rule_id)
        if not rule:
            return handle_error('GST rule not found', 404, callback)
        
        db.session.delete(rule)
        db.session.commit()
        
        return handle_success(None, 'GST rule deleted successfully', callback)
        
    except Exception as e:
        db.session.rollback()
        return handle_error('Failed to delete GST rule. Please try again.', 500, callback, detailed_error=str(e))


# ============================================================================
# Settings Endpoints
# ============================================================================

@app.route('/api/settings', methods=['GET'])
def get_settings():
    """Get application settings"""
    callback = get_jsonp_callback()
    
    try:
        settings = Settings.get_settings()
        return handle_success(settings.to_dict(), callback=callback)
    except Exception as e:
        return handle_error('Failed to fetch settings. Please try again.', 500, callback, detailed_error=str(e))


@app.route('/api/gst', methods=['PUT'])
@require_auth
@require_role('Owner', 'Admin')
def update_gst():
    """Update GST rate - requires authentication and Admin+ role"""
    callback = get_jsonp_callback()
    
    try:
        data = request.get_json()
        
        # Handle both 'gst' and 'gstRate' field names for backward compatibility
        gst_value = data.get('gst') or data.get('gstRate')
        if gst_value is None:
            return handle_error('GST rate is required', 400, callback)
        
        try:
            gst_rate = Decimal(str(gst_value))
            if gst_rate < 0 or gst_rate > 100:
                return handle_error('GST rate must be between 0 and 100', 400, callback)
        except (ValueError, TypeError):
            return handle_error('Invalid GST rate format', 400, callback)
        
        settings = Settings.get_settings()
        settings.gst_rate = gst_rate
        db.session.commit()
        
        return handle_success(settings.to_dict(), 'GST rate updated successfully', callback)
        
    except Exception as e:
        db.session.rollback()
        return handle_error('Failed to update GST rate. Please try again.', 500, callback, detailed_error=str(e))


@app.route('/api/settings', methods=['PUT'])
@require_auth
@require_role('Owner', 'Admin')
def update_settings():
    """Update application settings - requires authentication and Admin+ role"""
    callback = get_jsonp_callback()
    
    try:
        data = request.get_json()
        schema = SettingsUpdateSchema()
        errors = schema.validate(data)
        if errors:
            return handle_error(f'Validation error: {errors}', 400, callback)
        
        settings = Settings.get_settings()
        
        if 'gstRate' in data:
            settings.gst_rate = Decimal(str(data['gstRate']))
        if 'defaultValidityDays' in data:
            settings.default_validity_days = data['defaultValidityDays']
        
        db.session.commit()
        
        return handle_success(settings.to_dict(), 'Settings updated successfully', callback)
        
    except Exception as e:
        db.session.rollback()
        return handle_error('Failed to update settings. Please try again.', 500, callback, detailed_error=str(e))


# ============================================================================
# CSV Import/Export Endpoints
# ============================================================================

def generate_unique_product_id(product_name=None):
    """
    Generate a unique product_id using the same format as frontend create quotation section.
    Format: P{DDMMYYYY}{HHMMSS} (e.g., P16122025140648)
    If duplicate exists, adds milliseconds and random component for uniqueness.
    """
    now = datetime.now()
    
    # Format: DDMMYYYY
    date_str = now.strftime('%d%m%Y')
    
    # Format: HHMMSS
    time_str = now.strftime('%H%M%S')
    
    # Base product_id: P{DDMMYYYY}{HHMMSS}
    base_product_id = f"P{date_str}{time_str}"
    product_id = base_product_id
    
    # Check if product_id already exists
    if Item.query.filter_by(product_id=product_id).first() is not None:
        # Add milliseconds for uniqueness
        ms = now.microsecond // 1000  # Convert microseconds to milliseconds
        ms_str = str(ms).zfill(3)
        product_id = f"{base_product_id}{ms_str}"
        
        # If still exists, add random component
        if Item.query.filter_by(product_id=product_id).first() is not None:
            random_str = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(3))
            product_id = f"{base_product_id}{ms_str}{random_str}"
            
            # Final check - if still exists (very unlikely), use counter
            counter = 1
            while Item.query.filter_by(product_id=product_id).first() is not None:
                product_id = f"{base_product_id}{ms_str}{random_str}{counter}"
                counter += 1
                if counter > 1000:  # Safety limit
                    return f"P{int(now.timestamp())}"
    
    return product_id


@app.route('/api/export/items', methods=['GET'])
def export_items():
    """Export all items as CSV"""
    try:
        items = Item.query.order_by(Item.created_at.desc()).all()
        
        # Create CSV in memory
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Product ID', 'Item URL', 'Product Name', 'Type', 'Price', 'Description', 'Added By'])
        
        # Write data
        for item in items:
            writer.writerow([
                item.product_id,
                item.item_url or '',
                item.product_name,
                item.type or '',
                float(item.price) if item.price else 0.0,
                item.description or '',
                item.added_by or ''
            ])
        
        # Create response
        output.seek(0)
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = 'attachment; filename=items_export.csv'
        return response
        
    except Exception as e:
        callback = get_jsonp_callback()
        return handle_error('Failed to export items. Please try again.', 500, callback, detailed_error=str(e))


@app.route('/api/import/items', methods=['POST'])
@require_auth
@require_role('Owner', 'Admin', 'Manager')
def import_items():
    """Import items from CSV file - requires authentication and Manager+ role"""
    callback = get_jsonp_callback()
    
    try:
        if 'file' not in request.files:
            return handle_error('No file provided', 400, callback)
        
        file = request.files['file']
        if file.filename == '':
            return handle_error('No file selected', 400, callback)
        
        if not file.filename.endswith('.csv'):
            return handle_error('File must be a CSV', 400, callback)
        
        # Read CSV with proper encoding handling
        try:
            file_content = file.stream.read()
            # Try UTF-8 first, fallback to latin-1 if needed
            try:
                decoded_content = file_content.decode("UTF-8")
            except UnicodeDecodeError:
                decoded_content = file_content.decode("latin-1")
            stream = io.StringIO(decoded_content, newline=None)
            csv_reader = csv.DictReader(stream)
        except Exception as e:
            return handle_error(f'Failed to read CSV file: {str(e)}', 400, callback)
        
        imported_count = 0
        updated_count = 0
        error_count = 0
        errors = []
        
        # Helper function to get column value (case-insensitive, handles both old and new formats)
        def get_column(row, possible_names):
            """Get column value trying multiple possible column names (case-insensitive)"""
            for name in possible_names:
                # Try exact match first
                if name in row:
                    return row[name].strip() if row[name] else ''
                # Try case-insensitive match
                for key in row.keys():
                    if key.lower() == name.lower():
                        return row[key].strip() if row[key] else ''
            return ''
        
        for row_num, row in enumerate(csv_reader, start=2):  # Start at 2 (row 1 is header)
            try:
                # Skip completely empty rows
                if not any(row.values()):
                    continue
                
                # Get product_id (try both old and new column names)
                product_id = get_column(row, ['product_id', 'Product ID', 'productId'])
                
                # Validate required fields - product_name is required
                product_name = get_column(row, ['product_name', 'Product Name', 'productName'])
                if not product_name or not product_name.strip():
                    error_count += 1
                    errors.append(f'Row {row_num}: Product Name is required (skipping row)')
                    continue
                
                # Auto-generate product_id if missing (using same format as create quotation section)
                if not product_id:
                    product_id = generate_unique_product_id()
                
                # Parse price with validation
                price_str = get_column(row, ['price', 'Price'])
                price = Decimal('0')
                if price_str:
                    try:
                        # Remove currency symbols, commas, and whitespace
                        price_clean = str(price_str).strip()
                        # Remove currency symbols (₹, $, €, etc.)
                        price_clean = price_clean.replace('₹', '').replace('$', '').replace('€', '').replace('£', '').replace(',', '')
                        # Remove any remaining whitespace
                        price_clean = price_clean.strip()
                        
                        if price_clean:
                            price = Decimal(price_clean)
                            if price < 0:
                                price = Decimal('0')
                        else:
                            # Empty or whitespace-only price
                            error_count += 1
                            errors.append(f'Row {row_num}: Empty price for Product "{product_name}", using 0')
                            price = Decimal('0')
                    except (ValueError, TypeError, Exception) as e:
                        error_count += 1
                        errors.append(f'Row {row_num}: Invalid price "{price_str}" for Product "{product_name}", using 0. Error: {str(e)}')
                        price = Decimal('0')
                else:
                    # No price provided
                    error_count += 1
                    errors.append(f'Row {row_num}: Missing price for Product "{product_name}", using 0')
                    price = Decimal('0')
                
                # Get other fields (try both old and new column names)
                item_url = get_column(row, ['item_url', 'Item URL', 'Website URL', 'websiteUrl'])
                item_type = get_column(row, ['type', 'Type'])
                description = get_column(row, ['description', 'Description'])
                added_by = get_column(row, ['added_by', 'Added By', 'addedBy'])
                
                # Parse GST from CSV without recalculating or changing the value
                # Whatever numeric value is present in the CSV (with or without % sign)
                # will be stored as-is in the database.
                gst_str = get_column(row, ['gst', 'GST'])
                gst = Decimal('0')
                if gst_str:
                    try:
                        # Remove % sign if present and trim whitespace
                        gst_clean = str(gst_str).replace('%', '').strip()
                        # Store the numeric value directly (e.g., "18" or "18.0" stays 18)
                        gst = Decimal(gst_clean) if gst_clean else Decimal('0')
                    except (ValueError, TypeError, Exception):
                        # Fallback: try raw string, otherwise default to 0
                        try:
                            gst = Decimal(str(gst_str))
                        except (ValueError, TypeError, Exception):
                            gst = Decimal('0')
                
                # Parse total_price
                total_price_str = get_column(row, ['total_price', 'Total Price', 'totalPrice'])
                total_price = Decimal('0')
                if total_price_str:
                    try:
                        total_price = Decimal(str(total_price_str))
                    except (ValueError, TypeError):
                        # Auto-calculate if not provided
                        total_price = price + gst
                else:
                    # Auto-calculate if not provided
                    total_price = price + gst
                
                # Check if item exists
                item = Item.query.filter_by(product_id=product_id).first()
                
                if item:
                    # Update existing
                    item.item_url = item_url or item.item_url
                    item.product_name = product_name
                    item.type = item_type or item.type
                    item.price = price
                    item.gst = gst
                    item.total_price = total_price
                    item.description = description or item.description
                    item.added_by = added_by or item.added_by
                    updated_count += 1
                else:
                    # Create new
                    item = Item(
                        product_id=product_id,
                        item_url=item_url,
                        product_name=product_name,
                        type=item_type,
                        price=price,
                        gst=gst,
                        total_price=total_price,
                        description=description,
                        added_by=added_by
                    )
                    db.session.add(item)
                    imported_count += 1
            except Exception as e:
                error_count += 1
                errors.append(f'Row {row_num}: Error processing row - {str(e)}')
                continue
        
        # Commit all changes
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return handle_error(f'Database error during import: {str(e)}', 500, callback)
        
        # Prepare response message
        message = f'Import complete: {imported_count} imported, {updated_count} updated'
        if error_count > 0:
            message += f', {error_count} errors'
        
        response_data = {
            'imported': imported_count,
            'updated': updated_count,
            'total': imported_count + updated_count,
            'errors': error_count
        }
        
        if errors and len(errors) <= 10:  # Include errors if not too many
            response_data['error_details'] = errors
        
        return handle_success(response_data, message, callback)
        
    except Exception as e:
        db.session.rollback()
        import traceback
        error_details = traceback.format_exc()
        logging.error(f'Import items error: {error_details}')
        return handle_error(f'Failed to import items: {str(e)}', 500, callback, detailed_error=str(e))


# ============================================================================
# Health Check Endpoint
# ============================================================================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint with database connection status"""
    callback = get_jsonp_callback()
    
    try:
        # Test database connection
        db.session.execute(db.text('SELECT 1'))
        
        # Get connection pool info from SQLAlchemy engine (non-sensitive)
        pool_info = {}
        try:
            engine = db.engine
            pool = engine.pool
            pool_info = {
                'pool_size': pool.size(),
                'checked_in': pool.checkedin(),
                'checked_out': pool.checkedout(),
                'overflow': pool.overflow(),
                'max_overflow': getattr(pool, '_max_overflow', None)
            }
        except Exception:
            pass  # Ignore if pool info unavailable
        
        health_data = {
            'status': 'healthy',
            'database': 'connected',
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Only include non-sensitive connection pool info
        # Do not expose database host, port, database name, or user for security
        if pool_info:
            health_data['connection_pool'] = pool_info
        
        return handle_success(health_data, callback=callback)
    except Exception as e:
        return handle_error('Health check failed. Please try again.', 500, callback, detailed_error=str(e))


@app.route('/api/session-info', methods=['GET'])
def get_session_info():
    """Get session timeout information for frontend"""
    callback = get_jsonp_callback()
    
    try:
        session_timeout = SESSION_TIMEOUT_SECONDS
        session_info = {
            'timeout_seconds': session_timeout,
            'timeout_minutes': session_timeout // 60,
            'timeout_hours': session_timeout // 3600,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return handle_success(session_info, callback=callback)
    except Exception as e:
        return handle_error('Failed to get session information. Please try again.', 500, callback, detailed_error=str(e))


# ============================================================================
# Frontend Routes - Serve HTML files
# ============================================================================

@app.route('/')
def index():
    """Serve login page as default"""
    response = send_from_directory(FRONTEND_DIR, 'index.html')
    # HTML files should not be cached
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# Static file routes - Minimal fallback for development only
# In production (cPanel), Apache should serve static files directly
# These routes are only used in development mode
if not IS_PRODUCTION:
    @app.route('/images/<path:filename>')
    def serve_images(filename):
        """Serve image files from images directory (development only)"""
        try:
            response = send_from_directory(os.path.join(FRONTEND_DIR, 'images'), filename)
            response.headers['Cache-Control'] = 'public, max-age=2592000'
            return response
        except Exception:
            callback = get_jsonp_callback()
            return handle_error('Image file not found', 404, callback)
    
    @app.route('/css/<path:filename>')
    def serve_css(filename):
        """Serve CSS files from css directory (development only)"""
        try:
            response = send_from_directory(os.path.join(FRONTEND_DIR, 'css'), filename)
            response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
            return response
        except Exception:
            callback = get_jsonp_callback()
            return handle_error('CSS file not found', 404, callback)
    
    @app.route('/js/<path:filename>')
    def serve_js(filename):
        """Serve JavaScript files from js directory (development only)"""
        try:
            response = send_from_directory(os.path.join(FRONTEND_DIR, 'js'), filename)
            response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
            return response
        except Exception:
            callback = get_jsonp_callback()
            return handle_error('JavaScript file not found', 404, callback)

@app.route('/<path:filename>')
def serve_frontend(filename):
    """
    Serve frontend HTML files - minimal fallback for development.
    In production, Apache should serve static files directly.
    This route only handles HTML pages.
    """
    # Don't serve API routes through this handler
    if filename.startswith('api/'):
        callback = get_jsonp_callback()
        return handle_error('API endpoint not found', 404, callback)
    
    # Don't serve static files (CSS, JS, images) - they have their own routes
    if filename.startswith(('css/', 'js/', 'images/')):
        callback = get_jsonp_callback()
        return handle_error('Static file not found', 404, callback)
    
    # Only serve HTML files through Flask
    # Static files (CSS, JS, images) should be served by Apache in production
    if not filename.endswith('.html'):
        filename = f'{filename}.html'
    
    # Serve HTML files from root directory
    try:
        response = send_from_directory(FRONTEND_DIR, filename)
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    except Exception:
        pass
    
    # Fallback to login page
    try:
        response = send_from_directory(FRONTEND_DIR, 'index.html')
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        return response
    except Exception:
        callback = get_jsonp_callback()
        return handle_error('Page not found', 404, callback)


# ============================================================================
# Error Handlers
# ============================================================================

@app.errorhandler(429)
def ratelimit_handler(e):
    """
    Handle rate limit exceeded errors (429 Too Many Requests).
    Returns JSON response with rate limit information.
    Flask-Limiter automatically raises 429 errors when limits are exceeded.
    """
    callback = get_jsonp_callback()
    
    # Get rate limit information from the exception
    description = str(e.description) if hasattr(e, 'description') else 'Too many requests'
    
    # Extract rate limit details if available
    retry_after = None
    if hasattr(e, 'retry_after'):
        retry_after = e.retry_after
    elif hasattr(e, 'headers') and 'Retry-After' in e.headers:
        retry_after = e.headers['Retry-After']
    
    # Try to get retry-after from response headers
    try:
        if hasattr(e, 'response') and e.response:
            retry_after = e.response.headers.get('Retry-After')
    except Exception:
        pass
    
    error_message = 'Too many requests. Please try again later.'
    if retry_after:
        try:
            retry_seconds = int(retry_after)
            if retry_seconds < 60:
                error_message = f'Too many requests. Please try again in {retry_seconds} seconds.'
            else:
                minutes = retry_seconds // 60
                error_message = f'Too many requests. Please try again in {minutes} minute(s).'
        except (ValueError, TypeError):
            error_message = 'Too many requests. Please try again later.'
    
    error_data = {
        'success': False,
        'error': error_message,
        'message': error_message
    }
    
    if retry_after:
        error_data['retry_after'] = retry_after
    
    response = jsonp_response(error_data, callback)
    response.status_code = 429
    
    # Set Retry-After header if available
    if retry_after:
        response.headers['Retry-After'] = str(retry_after)
    else:
        # Default to 60 seconds if not specified
        response.headers['Retry-After'] = '60'
    
    return response



@app.after_request
def after_request(response):
    """Ensure API errors return JSON content type"""
    # Check if request context is available
    try:
        path = request.path
    except RuntimeError:
        # Request context not available, return response as-is
        return response
    
    # If it's an API route and there's an error, ensure JSON content type
    if path.startswith('/api/') and response.status_code >= 400:
        # Check if response is HTML (error page from Flask)
        try:
            content_type = response.content_type or ''
            if 'text/html' in content_type or 'application/json' not in content_type:
                data = response.get_data(as_text=True)
                # If it's HTML error page, convert to JSON
                if data and (data.strip().startswith('<!DOCTYPE') or data.strip().startswith('<html')):
                    callback = get_jsonp_callback()
                    error_response, status_code = handle_error('Internal server error', response.status_code, callback)
                    return error_response
        except Exception:
            # If we can't check, ensure JSON content type anyway
            try:
                if not response.content_type or 'application/json' not in response.content_type:
                    callback = get_jsonp_callback()
                    error_response, status_code = handle_error('Internal server error', response.status_code, callback)
                    return error_response
            except Exception:
                pass  # If we can't fix it, return original response

    return response


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors - try to serve frontend if it's not an API call"""
    # Get request context if available
    try:
        path = request.path
        callback = get_jsonp_callback()
    except RuntimeError:
        # Request context not available
        path = ''
        callback = None
    
    # If it's an API call, return JSON error
    if path.startswith('/api/'):
        return handle_error('Endpoint not found', 404, callback)
    # Otherwise, try to serve login page
    try:
        return send_from_directory(FRONTEND_DIR, 'index.html')
    except Exception:
        return handle_error('Page not found', 404, callback)


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors - always return JSON for API routes"""
    import traceback
    import logging
    
    # Log error traceback for server logs (not exposed to client)
    error_details = traceback.format_exc()
    logging.error(f"Internal server error: {error_details}")
    
    # Only print in development
    if not IS_PRODUCTION:
        traceback.print_exc()
    
    # Get callback if request context is available
    try:
        callback = get_jsonp_callback()
        path = request.path
    except RuntimeError:
        # Request context not available (e.g., during app initialization)
        callback = None
        path = ''
    
    # Always return JSON for API routes with generic message
    if path.startswith('/api/'):
        error_response, status_code = handle_error(
            'An internal server error occurred. Please try again later.', 
            500, 
            callback,
            detailed_error=error_details
        )
        # Ensure proper content type header
        error_response.headers['Content-Type'] = 'application/json'
        return error_response, status_code
    # For non-API routes, return JSON anyway to avoid HTML errors
    error_response, status_code = handle_error(
        'An internal server error occurred. Please try again later.', 
        500, 
        callback,
        detailed_error=error_details
    )
    error_response.headers['Content-Type'] = 'application/json'
    return error_response, status_code


@app.errorhandler(Exception)
def handle_exception(e):
    """Handle all unhandled exceptions - ensure JSON response for API routes"""
    import traceback
    import logging
    
    # Log error traceback for server logs (not exposed to client)
    error_details = traceback.format_exc()
    logging.error(f"Unhandled exception: {error_details}")
    
    # Only print in development
    if not IS_PRODUCTION:
        traceback.print_exc()
    
    # Get request context if available
    try:
        path = request.path
        callback = get_jsonp_callback()
    except RuntimeError:
        # Request context not available (e.g., during app initialization)
        path = ''
        callback = None
    
    # Always return JSON for API routes
    if path.startswith('/api/'):
        try:
            db.session.rollback()
        except Exception:
            pass  # Ignore rollback errors
        
        # Don't expose internal error details in production
        error_message = 'An internal server error occurred. Please try again later.'
        error_response, status_code = handle_error(error_message, 500, callback, detailed_error=error_details)
        # Ensure proper content type header
        error_response.headers['Content-Type'] = 'application/json'
        return error_response, status_code
    
    # For non-API routes, let Flask's default handler deal with it
    # But we'll still try to return JSON if possible
    error_response, status_code = handle_error(
        'An error occurred. Please try again later.', 
        500, 
        callback,
        detailed_error=error_details
    )
    error_response.headers['Content-Type'] = 'application/json'
    return error_response, status_code


# ============================================================================
# Application Initialization
# ============================================================================

def initialize_app():
    """Initialize application and database"""
    import sys
    import traceback
    
    try:
        with app.app_context():
            # Only test connection - don't create SQLite database automatically
            # Database tables should be created manually in MySQL Workbench
            connection_result = test_connection(app)
            if connection_result:
                msg = "Database connection verified. Using existing database."
                if IS_PRODUCTION:
                    logging.info(msg)
                else:
                    print(msg)
            else:
                msg = "WARNING: Database connection test failed, but app will continue."
                if IS_PRODUCTION:
                    logging.warning(msg)
                else:
                    print(msg)
                logging.warning("Database features may not work until connection is established.")
    except Exception as e:
        error_msg = f"Error during application initialization: {str(e)}"
        if IS_PRODUCTION:
            logging.error(error_msg, exc_info=True)
        else:
            print(error_msg)
            traceback.print_exc()
        logging.warning("The application will continue to run, but some features may not work.")
        # Don't re-raise - allow app to start even if initialization fails


# Configure logging
# Use LOG_FILE environment variable if set, otherwise use default location
if IS_PRODUCTION:
    # Production logging configuration
    log_file_path = os.getenv('LOG_FILE', os.path.join(BASE_DIR, 'app.log'))
    
    # Try to use the specified log file path
    try:
        # Test if we can write to the log file
        test_file = open(log_file_path, 'a')
        test_file.close()
    except Exception:
        # Fallback to quotation_backend directory if specified path fails
        log_file_path = os.path.join(BASE_DIR, 'app.log')
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file_path),
            logging.StreamHandler()
        ]
    )
    logging.info(f"Production logging initialized. Log file: {log_file_path}")
else:
    # Development logging - more verbose
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

if __name__ == '__main__':
    # Development server mode
    # Initialize database on startup
    initialize_app()
    
    # Get host and port from environment or use defaults
    host = os.getenv('FLASK_HOST', '0.0.0.0')
    port = int(os.getenv('FLASK_PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Run development server
    print(f"Starting {'development' if debug else 'production'} server on {host}:{port}...")
    app.run(host=host, port=port, debug=debug)
else:
    # Production mode - Initialize when app is loaded (e.g., for WSGI servers like Passenger)
    # This is the path used by cPanel/Passenger
    initialize_app()
    logging.info("Application initialized for production (WSGI mode)")



