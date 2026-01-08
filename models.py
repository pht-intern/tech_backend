"""
SQLAlchemy database models for the quotation management system
"""
from database import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from decimal import Decimal


# ============================================================================
# User Model
# ============================================================================

class User(db.Model):
    """User model for authentication and user management"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False, index=True)
    name = db.Column(db.String(255))
    phone = db.Column(db.String(20))
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    quotations = db.relationship('Quotation', backref='creator', lazy='dynamic', foreign_keys='Quotation.created_by_user_id')
    logs = db.relationship('Log', backref='user_ref', lazy='dynamic', foreign_keys='Log.user_id')

    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check if provided password matches hash"""
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        """Convert user to dictionary"""
        return {
            'id': self.id,
            'email': self.email,
            'role': self.role,
            'name': self.name,
            'phone': self.phone,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def __repr__(self):
        return f'<User {self.email}>'


# ============================================================================
# Item/Product Model
# ============================================================================

class Item(db.Model):
    """Product/Item model"""
    __tablename__ = 'items'

    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    item_url = db.Column(db.Text)  # Changed from String(500) to Text to support long URLs
    product_name = db.Column(db.String(255), nullable=False, index=True)
    type = db.Column(db.String(100))
    price = db.Column(db.Numeric(10, 2), nullable=False)
    gst = db.Column(db.Numeric(10, 2), default=0, nullable=False)
    total_price = db.Column(db.Numeric(10, 2), default=0, nullable=False)
    description = db.Column(db.Text)
    added_by = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    quotation_items = db.relationship('QuotationItem', backref='item', lazy='dynamic', cascade='all, delete-orphan')

    def to_dict(self):
        """Convert item to dictionary"""
        return {
            'id': self.id,
            'productId': self.product_id,
            'itemUrl': self.item_url,
            'productName': self.product_name,
            'type': self.type,
            'price': float(self.price) if self.price else 0.0,
            'gst': float(self.gst) if self.gst else 0.0,
            'totalPrice': float(self.total_price) if self.total_price else 0.0,
            'description': self.description,
            'addedBy': self.added_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def __repr__(self):
        return f'<Item {self.product_id}: {self.product_name}>'


# ============================================================================
# Temp Model (Same structure as Item for storing edited prices/GST)
# ============================================================================

class Temp(db.Model):
    """Temporary product/Item model for storing edited prices and GST"""
    __tablename__ = 'temp'

    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    item_url = db.Column(db.Text)
    product_name = db.Column(db.String(255), nullable=False, index=True)
    type = db.Column(db.String(100))
    price = db.Column(db.Numeric(10, 2), nullable=False)
    gst = db.Column(db.Numeric(10, 2), default=0, nullable=False)
    total_price = db.Column(db.Numeric(10, 2), default=0, nullable=False)
    description = db.Column(db.Text)
    added_by = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def to_dict(self):
        """Convert temp item to dictionary"""
        return {
            'id': self.id,
            'productId': self.product_id,
            'itemUrl': self.item_url,
            'productName': self.product_name,
            'type': self.type,
            'price': float(self.price) if self.price else 0.0,
            'gst': float(self.gst) if self.gst else 0.0,
            'totalPrice': float(self.total_price) if self.total_price else 0.0,
            'description': self.description,
            'addedBy': self.added_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def __repr__(self):
        return f'<Temp {self.product_id}: {self.product_name}>'


# ============================================================================
# Customer Model
# ============================================================================

class Customer(db.Model):
    """Customer model"""
    __tablename__ = 'customers'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, index=True)
    phone = db.Column(db.String(20), nullable=False, index=True)
    email = db.Column(db.String(255))
    address = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    quotations = db.relationship('Quotation', backref='customer_ref', lazy='dynamic', foreign_keys='Quotation.customer_id')

    def to_dict(self):
        """Convert customer to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'phone': self.phone,
            'email': self.email,
            'address': self.address,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def __repr__(self):
        return f'<Customer {self.name}>'


# ============================================================================
# Quotation Models
# ============================================================================

class Quotation(db.Model):
    """Quotation model"""
    __tablename__ = 'quotations'

    id = db.Column(db.Integer, primary_key=True)
    quotation_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    date_created = db.Column(db.String(50), nullable=False)  # Stored as string in 'en-IN' format
    
    # Customer information (embedded or foreign key)
    # Option 1: Store as JSON (matches frontend structure)
    customer_name = db.Column(db.String(255), nullable=False)
    customer_phone = db.Column(db.String(20), nullable=False, index=True)
    customer_email = db.Column(db.String(255))
    customer_address = db.Column(db.Text)
    
    # Option 2: Foreign key to Customer table (optional)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=True)
    
    # Financial fields
    sub_total = db.Column(db.Numeric(10, 2), nullable=False)
    discount_percent = db.Column(db.Numeric(5, 2), nullable=False, default=0)
    discount_amount = db.Column(db.Numeric(10, 2), nullable=False, default=0)
    total_gst_amount = db.Column(db.Numeric(10, 2), nullable=False, default=0)
    grand_total = db.Column(db.Numeric(10, 2), nullable=False)
    
    # Metadata
    created_by = db.Column(db.String(255))  # Username/email prefix
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    items = db.relationship('QuotationItem', backref='quotation', lazy='dynamic', cascade='all, delete-orphan')

    def to_dict(self):
        """Convert quotation to dictionary"""
        return {
            'id': self.id,
            'quotationId': self.quotation_id,
            'dateCreated': self.date_created,
            'customer': {
                # Expose empty-string DB values as null in the API for clarity
                'name': self.customer_name or None,
                'phone': self.customer_phone,
                'email': self.customer_email,
                'address': self.customer_address
            },
            'items': [item.to_dict() for item in self.items],
            'subTotal': float(self.sub_total) if self.sub_total else 0.0,
            'discountPercent': float(self.discount_percent) if self.discount_percent else 0.0,
            'discountAmount': float(self.discount_amount) if self.discount_amount else 0.0,
            'totalGstAmount': float(self.total_gst_amount) if self.total_gst_amount else 0.0,
            'grandTotal': float(self.grand_total) if self.grand_total else 0.0,
            'createdBy': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def __repr__(self):
        return f'<Quotation {self.quotation_id}>'


class QuotationItem(db.Model):
    """Quotation items (many-to-many relationship with additional fields)"""
    __tablename__ = 'quotation_items'

    id = db.Column(db.Integer, primary_key=True)
    quotation_id = db.Column(db.Integer, db.ForeignKey('quotations.id'), nullable=False, index=True)
    item_id = db.Column(db.Integer, db.ForeignKey('items.id'), nullable=True)  # Optional reference to Item
    product_id = db.Column(db.String(50), nullable=False)  # Store product_id directly
    product_name = db.Column(db.String(255), nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    gst_rate = db.Column(db.Numeric(5, 2), nullable=False, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self):
        """Convert quotation item to dictionary"""
        return {
            'id': self.id,
            'productId': self.product_id,
            'productName': self.product_name,
            'price': float(self.price) if self.price else 0.0,
            'quantity': self.quantity,
            'gstRate': float(self.gst_rate) if self.gst_rate else 0.0
        }

    def __repr__(self):
        return f'<QuotationItem {self.product_id} x{self.quantity}>'


# ============================================================================
# GST Rule Model
# ============================================================================

class GstRule(db.Model):
    """GST rule model for product-specific GST rates"""
    __tablename__ = 'gst_rules'

    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(255), nullable=False, index=True)
    percent = db.Column(db.Numeric(5, 2), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def to_dict(self):
        """Convert GST rule to dictionary"""
        return {
            'id': self.id,
            'productName': self.product_name,
            'percent': float(self.percent) if self.percent else 0.0,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def __repr__(self):
        return f'<GstRule {self.product_name}: {self.percent}%>'


# ============================================================================
# Settings Model
# ============================================================================

class Settings(db.Model):
    """Application settings model (singleton pattern)"""
    __tablename__ = 'settings'

    id = db.Column(db.Integer, primary_key=True)
    gst_rate = db.Column(db.Numeric(5, 2), nullable=False, default=18.00)
    default_validity_days = db.Column(db.Integer, nullable=False, default=30)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    @classmethod
    def get_settings(cls):
        """Get or create settings (singleton)"""
        settings = cls.query.first()
        if not settings:
            settings = cls()
            db.session.add(settings)
            db.session.commit()
        return settings

    def to_dict(self):
        """Convert settings to dictionary"""
        return {
            'id': self.id,
            'gstRate': float(self.gst_rate) if self.gst_rate else 18.0,
            'defaultValidityDays': self.default_validity_days,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def __repr__(self):
        return f'<Settings GST: {self.gst_rate}%, Validity: {self.default_validity_days} days>'


# ============================================================================
# Log/Audit Model
# ============================================================================

class Log(db.Model):
    """Audit log model"""
    __tablename__ = 'logs'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    action = db.Column(db.String(255), nullable=False, index=True)
    role = db.Column(db.String(50), nullable=False, index=True)
    details = db.Column(db.Text)
    user = db.Column(db.String(255))  # Username/email prefix
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self):
        """Convert log to dictionary"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'action': self.action,
            'role': self.role,
            'details': self.details,
            'user': self.user,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    def __repr__(self):
        return f'<Log {self.action} by {self.user}>'

