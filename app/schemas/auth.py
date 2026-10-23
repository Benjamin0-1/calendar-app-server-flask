from marshmallow import ValidationError, fields, validate, validates_schema

from app.schemas.base import RequestSchema


def required(message, **kwargs):
    return fields.String(required=True, error_messages={'required': message}, **kwargs)


class FlagErrorSchema(RequestSchema):
    """Login and signup answer validation errors with a flag, e.g. {"missingData": true}."""

    def error_body(self, message):
        return {message: True}


class LoginSchema(FlagErrorSchema):
    email = required('missingData')
    password = required('missingData')


class SignupSchema(FlagErrorSchema):
    first_name = required('missingData', data_key='firstName')
    last_name = required('missingData', data_key='lastName')
    email = required('missingData', validate=validate.Regexp(r'^[\w\.-]+@[\w\.-]+\.\w+$', error='invalidEmail'))
    password = required('missingData')


class RefreshTokenSchema(RequestSchema):
    refresh_token = required('Refresh token is missing', data_key='refreshToken')


class PasswordResetRequestSchema(RequestSchema):
    email = required('Email is required')


class PasswordResetSchema(RequestSchema):
    email = required('Missing required data')
    otp = required('Missing required data')
    new_password = required('Missing required data', data_key='newPassword')
    confirm_new_password = required('Missing required data', data_key='confirmNewPassword')

    @validates_schema
    def passwords_match(self, data, **kwargs):
        if data['new_password'] != data['confirm_new_password']:
            raise ValidationError("Passwords don't match")


class ProfileUpdateSchema(RequestSchema):
    first_name = fields.String(data_key='firstName')
    last_name = fields.String(data_key='lastName')

    @validates_schema
    def something_to_update(self, data, **kwargs):
        if not data:
            raise ValidationError("At least one parameter to be updated is required")


class PasswordUpdateSchema(RequestSchema):
    current_password = required('All fields are required', data_key='currentPassword')
    new_password = required('All fields are required', data_key='newPassword')
    confirm_new_password = required('All fields are required', data_key='confirmNewPassword')


class ResendConfirmationSchema(RequestSchema):
    email = required('Email is required to resend confirmation link')


class GoogleLoginSchema(RequestSchema):
    google_token = required('Google token, email, and user ID are required', data_key='googleToken')
    email = required('Google token, email, and user ID are required')
    user_id = fields.Raw(required=True, data_key='userId',
                         error_messages={'required': 'Google token, email, and user ID are required'})
