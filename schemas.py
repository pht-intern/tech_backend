"""
Marshmallow schemas for request/response validation and serialization
"""
from marshmallow import Schema, fields, validate, EXCLUDE


# ============================================================================
# User Schemas
# ============================================================================

class UserSchema(Schema):
    """Schema for user data"""
    id = fields.Int(dump_only=True)
    email = fields.Email(required=True, validate=validate.Length(min=5, max=255))
    password = fields.Str(load_only=True, required=True, validate=validate.Length(min=6))
    role = fields.Str(required=True, validate=validate.OneOf(['Owner', 'Admin', 'Manager', 'Sales', 'Accountant', 'Employee']))
    name = fields.Str(validate=validate.Length(max=255))
    phone = fields.Str(validate=validate.Length(max=20))
    latitude = fields.Float(allow_none=True)
    longitude = fields.Float(allow_none=True)
    created_at = fields.DateTime(dump_only=True)
    updated_at = fields.DateTime(dump_only=True)
    is_active = fields.Bool(missing=True)


class UserLoginSchema(Schema):
    """Schema for user login"""
    email = fields.Email(required=True)
    password = fields.Str(required=True, load_only=True)


class UserResponseSchema(Schema):
    """Schema for user response (without password)"""
    id = fields.Int()
    email = fields.Email()
    role = fields.Str()
    name = fields.Str()
    phone = fields.Str()
    latitude = fields.Float(allow_none=True)
    longitude = fields.Float(allow_none=True)
    created_at = fields.DateTime()
    updated_at = fields.DateTime()
    is_active = fields.Bool()


# ============================================================================
# Item/Product Schemas
# ============================================================================

class ItemSchema(Schema):
    """Schema for product/item data"""
    id = fields.Int(dump_only=True)
    product_id = fields.Str(required=True, validate=validate.Length(min=1, max=50), data_key='productId')
    item_url = fields.Str(validate=validate.URL(relative=True, require_tld=False), allow_none=True, data_key='itemUrl')
    product_name = fields.Str(required=True, validate=validate.Length(min=1, max=255), data_key='productName')
    type = fields.Str(validate=validate.Length(max=100))
    price = fields.Decimal(required=True, validate=validate.Range(min=0), places=2, as_string=True)
    description = fields.Str(allow_none=True)
    added_by = fields.Str(validate=validate.Length(max=255), data_key='addedBy')
    created_at = fields.DateTime(dump_only=True)
    updated_at = fields.DateTime(dump_only=True)


class ItemCreateSchema(Schema):
    """Schema for creating a new item"""
    productId = fields.Str(required=True, validate=validate.Length(min=1, max=50))
    itemUrl = fields.Str(validate=validate.URL(relative=True, require_tld=False), allow_none=True)
    productName = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    type = fields.Str(validate=validate.Length(max=100))
    price = fields.Decimal(required=True, validate=validate.Range(min=0), places=2, as_string=True)
    gst = fields.Decimal(validate=validate.Range(min=0), places=2, as_string=True, allow_none=True)
    totalPrice = fields.Decimal(validate=validate.Range(min=0), places=2, as_string=True, allow_none=True)
    description = fields.Str(allow_none=True)
    addedBy = fields.Str(validate=validate.Length(max=255))


class ItemUpdateSchema(Schema):
    """Schema for updating an item"""
    class Meta:
        # Allow extra fields (e.g., productId, addedBy) to be ignored instead of causing validation errors
        unknown = EXCLUDE

    itemUrl = fields.Str(validate=validate.URL(relative=True, require_tld=False), allow_none=True)
    productName = fields.Str(validate=validate.Length(min=1, max=255))
    type = fields.Str(validate=validate.Length(max=100))
    price = fields.Decimal(validate=validate.Range(min=0), places=2, as_string=True, allow_none=True)
    gst = fields.Decimal(validate=validate.Range(min=0), places=2, as_string=True, allow_none=True)
    totalPrice = fields.Decimal(validate=validate.Range(min=0), places=2, as_string=True, allow_none=True)
    description = fields.Str(allow_none=True)


# ============================================================================
# Customer Schemas
# ============================================================================

class CustomerSchema(Schema):
    """Schema for customer data"""
    id = fields.Int(dump_only=True)
    name = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    phone = fields.Str(required=True, validate=validate.Length(min=10, max=20))
    email = fields.Email(allow_none=True)
    address = fields.Str(allow_none=True)
    created_at = fields.DateTime(dump_only=True)
    updated_at = fields.DateTime(dump_only=True)


class CustomerEmbeddedSchema(Schema):
    """Schema for customer data embedded in quotations

    Note: Unlike the main CustomerSchema, the name here is optional to allow
    creating quotations with only a phone number (common in quick-sale flows).
    """
    # Name can be omitted or null; if provided, it must not exceed 255 chars.
    name = fields.Str(required=False, allow_none=True,
                      validate=validate.Length(max=255))
    phone = fields.Str(required=True, validate=validate.Length(min=10, max=20))
    email = fields.Email(allow_none=True)
    address = fields.Str(allow_none=True)


# ============================================================================
# Quotation Item Schemas
# ============================================================================

class QuotationItemSchema(Schema):
    """Schema for items within a quotation"""
    product_id = fields.Str(required=True, data_key='productId')
    product_name = fields.Str(required=True, data_key='productName')
    price = fields.Decimal(required=True, validate=validate.Range(min=0), places=2, as_string=True)
    quantity = fields.Int(required=True, validate=validate.Range(min=1))
    gst_rate = fields.Decimal(required=True, validate=validate.Range(min=0, max=100), places=2, as_string=True, data_key='gstRate')


class QuotationItemCreateSchema(Schema):
    """Schema for quotation items in create requests"""
    productId = fields.Str(required=True)
    productName = fields.Str(required=True)
    price = fields.Decimal(required=True, validate=validate.Range(min=0), places=2, as_string=True)
    quantity = fields.Int(required=True, validate=validate.Range(min=1))
    gstRate = fields.Decimal(required=True, validate=validate.Range(min=0, max=100), places=2, as_string=True)


# ============================================================================
# Quotation Schemas
# ============================================================================

class QuotationSchema(Schema):
    """Schema for quotation data"""
    id = fields.Int(dump_only=True)
    quotation_id = fields.Str(required=True, validate=validate.Length(min=1, max=50), data_key='quotationId')
    date_created = fields.Str(required=True, data_key='dateCreated')
    customer = fields.Nested(CustomerEmbeddedSchema, required=True)
    items = fields.Nested(QuotationItemSchema, many=True, required=True)
    sub_total = fields.Decimal(required=True, validate=validate.Range(min=0), places=2, as_string=True, data_key='subTotal')
    discount_percent = fields.Decimal(required=True, validate=validate.Range(min=0, max=100), places=2, as_string=True, data_key='discountPercent')
    discount_amount = fields.Decimal(required=True, validate=validate.Range(min=0), places=2, as_string=True, data_key='discountAmount')
    total_gst_amount = fields.Decimal(required=True, validate=validate.Range(min=0), places=2, as_string=True, data_key='totalGstAmount')
    grand_total = fields.Decimal(required=True, validate=validate.Range(min=0), places=2, as_string=True, data_key='grandTotal')
    created_by = fields.Str(validate=validate.Length(max=255), data_key='createdBy')
    created_at = fields.DateTime(dump_only=True)
    updated_at = fields.DateTime(dump_only=True)


class QuotationCreateSchema(Schema):
    """Schema for creating a new quotation"""
    quotationId = fields.Str(required=True, validate=validate.Length(min=1, max=50))
    dateCreated = fields.Str(required=True)
    customer = fields.Nested(CustomerEmbeddedSchema, required=True)
    items = fields.Nested(QuotationItemCreateSchema, many=True, required=True, validate=validate.Length(min=1))
    subTotal = fields.Decimal(required=True, validate=validate.Range(min=0), places=2, as_string=True)
    discountPercent = fields.Decimal(required=True, validate=validate.Range(min=0, max=100), places=2, as_string=True)
    discountAmount = fields.Decimal(required=True, validate=validate.Range(min=0), places=2, as_string=True)
    totalGstAmount = fields.Decimal(required=True, validate=validate.Range(min=0), places=2, as_string=True)
    grandTotal = fields.Decimal(required=True, validate=validate.Range(min=0), places=2, as_string=True)
    createdBy = fields.Str(validate=validate.Length(max=255))


# ============================================================================
# GST Rule Schemas
# ============================================================================

class GstRuleSchema(Schema):
    """Schema for GST rules"""
    id = fields.Int(dump_only=True)
    product_name = fields.Str(required=True, validate=validate.Length(min=1, max=255), data_key='productName')
    percent = fields.Decimal(required=True, validate=validate.Range(min=0, max=100), places=2, as_string=True)
    created_at = fields.DateTime(dump_only=True)
    updated_at = fields.DateTime(dump_only=True)


class GstRuleCreateSchema(Schema):
    """Schema for creating a GST rule"""
    productName = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    percent = fields.Decimal(required=True, validate=validate.Range(min=0, max=100), places=2, as_string=True)


# ============================================================================
# Settings Schemas
# ============================================================================

class SettingsSchema(Schema):
    """Schema for application settings"""
    id = fields.Int(dump_only=True)
    gst_rate = fields.Decimal(required=True, validate=validate.Range(min=0, max=100), places=2, as_string=True, data_key='gstRate')
    default_validity_days = fields.Int(required=True, validate=validate.Range(min=1, max=365), data_key='defaultValidityDays')
    updated_at = fields.DateTime(dump_only=True)


class SettingsUpdateSchema(Schema):
    """Schema for updating settings"""
    class Meta:
        unknown = EXCLUDE  # Ignore unknown fields (e.g., brand, companyGstId stored in localStorage)
    
    gstRate = fields.Decimal(validate=validate.Range(min=0, max=100), places=2, as_string=True, allow_none=True)
    defaultValidityDays = fields.Int(validate=validate.Range(min=1, max=365), allow_none=True)


# ============================================================================
# Log/Audit Schemas
# ============================================================================

class LogSchema(Schema):
    """Schema for audit logs"""
    id = fields.Int(dump_only=True)
    timestamp = fields.DateTime(dump_only=True)
    action = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    role = fields.Str(required=True, validate=validate.Length(max=50))
    details = fields.Str(allow_none=True)
    user = fields.Str(validate=validate.Length(max=255))
    created_at = fields.DateTime(dump_only=True)


class LogCreateSchema(Schema):
    """Schema for creating a log entry"""
    action = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    role = fields.Str(required=True, validate=validate.Length(max=50))
    details = fields.Str(allow_none=True)
    user = fields.Str(validate=validate.Length(max=255))


# ============================================================================
# Response Schemas
# ============================================================================

class SuccessResponseSchema(Schema):
    """Schema for success responses"""
    success = fields.Bool()
    message = fields.Str()
    data = fields.Raw(allow_none=True)


class ErrorResponseSchema(Schema):
    """Schema for error responses"""
    success = fields.Bool()
    error = fields.Str()
    message = fields.Str(allow_none=True)


# ============================================================================
# CSV Import/Export Schemas
# ============================================================================

class ItemImportSchema(Schema):
    """Schema for CSV item import"""
    productId = fields.Str(required=True)
    itemUrl = fields.Str(allow_none=True)
    productName = fields.Str(required=True)
    type = fields.Str(allow_none=True)
    price = fields.Decimal(required=True, validate=validate.Range(min=0), places=2, as_string=True)
    description = fields.Str(allow_none=True)
    addedBy = fields.Str(allow_none=True)

