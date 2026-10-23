from datetime import datetime

from flask import request
from marshmallow import EXCLUDE, Schema, ValidationError, fields, missing, pre_load

from app.errors import APIError


def parse_iso_date(value):
    return datetime.strptime(value, '%Y-%m-%d').date()


class RequestSchema(Schema):
    """
    Base for request validation schemas.

    Validation failures are answered with the same body and status code the endpoints have always
    returned: each failing field contributes its message, and the first one wins in this order —
    missing fields, then invalid fields (both in declaration order), then schema-level rules.
    """

    class Meta:
        unknown = EXCLUDE

    # the endpoints used to treat any falsy value ("", 0, null) as not provided (`if not value`).
    empty_values_are_missing = True

    @pre_load
    def drop_empty_values(self, data, **kwargs):
        if self.empty_values_are_missing and isinstance(data, dict):
            return {key: value for key, value in data.items() if value}
        return data

    def error_body(self, message):
        return {"error": message}

    def error_response(self, errors):
        declared = [(field.data_key or name, field) for name, field in self.load_fields.items()]
        missing_fields = [errors[key][0] for key, field in declared
                          if key in errors and field.error_messages['required'] in errors[key]]
        invalid_fields = [errors[key][0] for key, field in declared if key in errors]
        message = (missing_fields + invalid_fields + errors.get('_schema', []))[0]
        return self.error_body(message), 400

    def handle_error(self, error, data, **kwargs):
        body, status = self.error_response(error.messages)
        raise APIError(body, status) from error


class Parsed(fields.Field):
    """
    A field converted by a plain function; the conversion error's text becomes the validation message.
    Missing values are passed to the function as None.
    """

    def __init__(self, parse, **kwargs):
        super().__init__(**kwargs)
        self.parse = parse

    def deserialize(self, value, attr=None, data=None, **kwargs):
        try:
            return self.parse(None if value is missing else value)
        except (TypeError, ValueError) as e:
            raise ValidationError(str(e)) from e


class LenientInteger(fields.Field):
    """An integer query arg that silently becomes None when malformed, like request.args.get(type=int)."""

    def _deserialize(self, value, attr, data, **kwargs):
        try:
            return int(value)
        except (TypeError, ValueError):
            return None


def load_json(schema_class):
    return schema_class().load(request.get_json() or {})


def load_args(schema_class):
    return schema_class().load(request.args.to_dict())
