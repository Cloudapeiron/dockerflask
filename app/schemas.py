from marshmallow import Schema, fields, validate, ValidationError, post_load
import logging

logger = logging.getLogger(__name__)


class UserRegistrationSchema(Schema):
    """Schema for user registration validation."""
    username = fields.Str(
        required=True,
        validate=[
            validate.Length(min=3, max=50),
            validate.Regexp(
                r'^[a-zA-Z0-9_]+$', error='Username can only contain letters, numbers, and underscores')
        ]
    )
    email = fields.Email(required=True)
    password = fields.Str(
        required=True,
        validate=validate.Length(min=8, max=128),
        load_only=True
    )
    confirm_password = fields.Str(
        required=True,
        load_only=True
    )

    @post_load
    def validate_passwords_match(self, data, **kwargs):
        """Validate that password and confirm_password match."""
        if data['password'] != data['confirm_password']:
            raise ValidationError('Passwords do not match', 'confirm_password')

        data.pop('confirm_password', None)
        return data


class UserLoginSchema(Schema):
    """Schema for user login validation."""
    username = fields.Str(
        required=True, validate=validate.Length(min=1, max=50))
    password = fields.Str(
        required=True, validate=validate.Length(min=1, max=128))


class PasswordChangeSchema(Schema):
    """Schema for password change validation."""
    current_password = fields.Str(
        required=True, validate=validate.Length(min=1, max=128))
    new_password = fields.Str(
        required=True,
        validate=validate.Length(min=8, max=128)
    )


class FileInfoSchema(Schema):
    """Schema for file information."""
    mime_type = fields.Str()
    category = fields.Str()
    size = fields.Int()


class FileUploadResponseSchema(Schema):
    """Schema for file upload response serialization - matches route response structure."""
    success = fields.Bool(required=True)
    file_id = fields.Str(allow_none=True)
    filename = fields.Str(allow_none=True)
    s3_url = fields.Str(allow_none=True)
    processing_task_id = fields.Str(allow_none=True)  # For async uploads
    notification_task_id = fields.Str(allow_none=True)  # For async uploads
    status = fields.Str(allow_none=True)  # For async uploads
    warning = fields.Str(allow_none=True)  # For async uploads
    file_info = fields.Nested(FileInfoSchema, allow_none=True)
    validation_warnings = fields.List(fields.Str(), load_default=list)
    error = fields.Str(allow_none=True)


class FileMetadataSchema(Schema):
    """Schema for file metadata serialization."""
    file_id = fields.Str(required=True)
    filename = fields.Str(required=True)
    original_filename = fields.Str(required=True)
    file_size = fields.Int(required=True)
    file_type = fields.Str(required=True)
    file_category = fields.Str(allow_none=True)
    upload_date = fields.DateTime(format='iso')
    s3_url = fields.Str(allow_none=True)
    validation_status = fields.Str(allow_none=True)
    validation_warnings = fields.List(fields.Str(), load_default=list)
    # Added for async processing
    processing_status = fields.Str(allow_none=True)


class FileListResponseSchema(Schema):
    """Schema for file list response."""
    files = fields.List(fields.Nested(FileMetadataSchema))
    total_count = fields.Int(load_default=0)
    user_id = fields.Str(allow_none=True)


class UserResponseSchema(Schema):
    """Schema for user data serialization (no sensitive data)."""
    id = fields.Int(required=True)
    username = fields.Str(required=True)
    email = fields.Email(required=True)
    created_at = fields.DateTime(format='iso', allow_none=True)
    is_active = fields.Bool(load_default=True)


class ErrorResponseSchema(Schema):
    """Schema for error responses."""
    error = fields.Str(required=True)
    message = fields.Str(allow_none=True)
    validation_errors = fields.Dict(allow_none=True)


class SuccessResponseSchema(Schema):
    """Schema for success responses."""
    success = fields.Bool(required=True)
    message = fields.Str(allow_none=True)
    data = fields.Raw(allow_none=True)


class FileValidationResponseSchema(Schema):
    """Schema for file validation responses."""
    valid = fields.Bool(required=True)
    mime_type = fields.Str(allow_none=True)
    category = fields.Str(allow_none=True)
    size = fields.Int(required=True)
    errors = fields.List(fields.Str(), load_default=list)
    warnings = fields.List(fields.Str(), load_default=list)


class TaskStatusSchema(Schema):
    """Schema for background task status responses."""
    task_id = fields.Str(required=True)
    # pending, started, success, failure, retry, revoked
    status = fields.Str(required=True)
    result = fields.Raw(allow_none=True)
    error = fields.Str(allow_none=True)
    progress = fields.Dict(allow_none=True)


class BatchProcessSchema(Schema):
    """Schema for batch processing requests."""
    file_ids = fields.List(fields.Str(), required=True,
                           validate=validate.Length(min=1, max=50))


# Validation helper functions
def validate_request_json(schema_class):
    """
    Decorator to validate JSON request data against a marshmallow schema.
    """
    def decorator(f):
        from functools import wraps

        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import request, jsonify

            if not request.is_json:
                return jsonify({'error': 'Content-Type must be application/json'}), 400

            try:
                schema = schema_class()
                validated_data = schema.load(request.get_json())

                # Add validated data to request object
                request.validated_data = validated_data

                return f(*args, **kwargs)

            except ValidationError as err:
                error_response = ErrorResponseSchema().dump({
                    'error': 'Validation failed',
                    'validation_errors': err.messages
                })
                return jsonify(error_response), 400
            except Exception as e:
                logger.error(f"Validation error: {e}")
                error_response = ErrorResponseSchema().dump({
                    'error': 'Invalid request data'
                })
                return jsonify(error_response), 400

        return decorated_function
    return decorator


def serialize_response(data, schema_class, many=False):
    """
    Helper function to serialize response data using marshmallow schemas.
    """
    try:
        schema = schema_class()
        if many:
            return schema.dump(data, many=True)
        else:
            return schema.dump(data)
    except Exception as e:
        logger.error(f"Serialization error: {e}")
        return {'error': 'Failed to serialize response data'}


def create_error_response(message, validation_errors=None, status_code=400):
    """
    Create a standardized error response.
    """
    error_data = {
        'error': message
    }
    if validation_errors:
        error_data['validation_errors'] = validation_errors

    response = ErrorResponseSchema().dump(error_data)
    return response, status_code


def create_success_response(message=None, data=None):
    """
    Create a standardized success response.
    """
    success_data = {
        'success': True
    }
    if message:
        success_data['message'] = message
    if data:
        success_data['data'] = data

    return SuccessResponseSchema().dump(success_data)
