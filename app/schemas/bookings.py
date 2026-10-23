from datetime import datetime

from marshmallow import Schema, ValidationError, fields, validates_schema

from app.schemas.base import LenientInteger, Parsed, RequestSchema, parse_iso_date


def required(message, field=fields.Raw, **kwargs):
    return field(required=True, error_messages={'required': message}, **kwargs)


# ---- requests ----

class BookingCreateSchema(RequestSchema):
    # every value is converted as sent (int(), strptime()), and conversion errors are reported with their text.
    empty_values_are_missing = False

    property_id = Parsed(int, data_key='propertyId')
    date = Parsed(parse_iso_date)
    customer_name = fields.Raw(data_key='customerName', load_default=None)

    @validates_schema
    def bookable(self, data, **kwargs):
        if data['date'] < datetime.utcnow().date():
            raise ValidationError("Can't book a date from the past.")
        if not data['customer_name']:
            raise ValidationError("Customer name is required")

    def error_response(self, errors):
        for key in ('propertyId', 'date'):
            if key in errors:
                return {"error": "Invalid user or property ID format", "details": errors[key][0]}, 400
        return super().error_response(errors)


class BookingUpdateSchema(RequestSchema):
    # newDate is validated by the service: the API checks property ownership before the date format.
    property_id = required('Missing property id', data_key='propertyId')
    current_date = required('Current date is required', data_key='currentDate')
    customer_name = fields.Raw(data_key='customerName', load_default=None)
    new_date = fields.Raw(data_key='newDate', load_default=None)


class BookingDeleteSchema(RequestSchema):
    property_id = required('Both property ID and date are required', data_key='propertyId')
    date = required('Both property ID and date are required')


class PropertyCreateSchema(RequestSchema):
    property_name = required('Missing propertyName in request data', data_key='propertyName')


class PropertyDeleteSchema(RequestSchema):
    property_id = required('Property ID is required', data_key='property_id')


class ArchivedBookingDeleteSchema(RequestSchema):
    date = fields.Date(format='%Y-%m-%d', required=True,
                       error_messages={'required': 'Date and property name is required.',
                                       'invalid': 'Invalid date format. Use YYYY-MM-DD'})
    property_name = required('Date and property name is required.', data_key='propertyName')


class BookingFilterSchema(RequestSchema):
    # date and propertyId are validated by the service: the API checks property ownership first.
    property_name = fields.String(data_key='propertyName', load_default=None)
    date = fields.String(load_default=None)
    customer_name = fields.String(data_key='customerName', load_default=None)
    property_id = fields.String(data_key='propertyId', load_default=None)
    sort_order = fields.String(load_default=None)
    page = LenientInteger(load_default=None)
    per_page = LenientInteger(data_key='perPage', load_default=None)


# ---- responses ----

class BookingSummarySchema(Schema):
    customer_name = fields.String(data_key='customerName')
    date = fields.Date(format='%a, %d %b %Y')


class PropertySummarySchema(Schema):
    id = fields.Integer()
    property_name = fields.String()


class CreatedPropertySchema(Schema):
    id = fields.Integer()
    property_name = fields.String(data_key='propertyName')
    user_id = fields.Integer(data_key='userId')
