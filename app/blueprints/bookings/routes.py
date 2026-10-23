from flask import jsonify
from flask_jwt_extended import jwt_required

from . import bookings
from app.schemas.base import load_args, load_json
from app.schemas.bookings import (
    ArchivedBookingDeleteSchema, BookingCreateSchema, BookingDeleteSchema, BookingFilterSchema,
    BookingUpdateSchema, PropertyCreateSchema, PropertyDeleteSchema,
)
from app.services import booking_service, property_service
from app.utils.get_user_id import get_user_id


# ---- bookings ----

@bookings.route('/', methods=['GET'], strict_slashes=False)
@jwt_required()
def view_user_bookings():
    return jsonify(booking_service.bookings_by_property(get_user_id()))


@bookings.route('/', methods=['POST'], strict_slashes=False)
@jwt_required()
def book_date():
    data = load_json(BookingCreateSchema)
    booking = booking_service.create_booking(get_user_id(), **data)
    return jsonify({"success": "Booking created successfully", "booking": booking}), 201


@bookings.route('/', methods=['PATCH'], strict_slashes=False)
@jwt_required()
def update_booking():
    data = load_json(BookingUpdateSchema)
    booking_service.update_booking(get_user_id(), **data)
    return jsonify({"message": "Booking updated successfully"})


@bookings.route('/', methods=['DELETE'], strict_slashes=False)
@jwt_required()
def delete_booking():
    data = load_json(BookingDeleteSchema)
    booking_service.delete_booking(get_user_id(), **data)
    return jsonify({"message": "Booking deleted successfully and archived in DeletedDate model"})


# default must be return all of the bookings at once (no pagination).
@bookings.route('/filter-bookings', methods=['GET'])
@jwt_required()
def filter_bookings():
    filters = load_args(BookingFilterSchema)
    return jsonify(booking_service.filter_bookings(get_user_id(), **filters))


# ---- properties ----

@bookings.route('/create-property', methods=['POST'])
@jwt_required()
def create_property():
    data = load_json(PropertyCreateSchema)
    property = property_service.create_property(get_user_id(), data['property_name'])
    return jsonify({"success": "Property created successfully", "property": property}), 201


@bookings.route('/delete-property', methods=['DELETE'])
@jwt_required()
def delete_property():
    data = load_json(PropertyDeleteSchema)
    property_service.delete_property(get_user_id(), data['property_id'])
    return jsonify({"message": "Property deleted successfully and associated bookings archived in DeletedDate model"})


@bookings.route('/user-properties')
@jwt_required()
def user_properties():
    return jsonify({"Your properties": property_service.user_properties(get_user_id())})


@bookings.route('/property-details/<int:id>')
@jwt_required()
def property_details(id):
    return jsonify(property_service.property_details(get_user_id(), id))


# ---- deleted (archived) bookings ----

@bookings.route('/view-deleted-bookings')
@jwt_required()
def view_deleted_bookings():
    return jsonify({"deletedBookings": booking_service.archived_bookings(get_user_id())})


@bookings.route('/delete-all-deleted-bookings', methods=['DELETE'])
@jwt_required()
def delete_all_deleted_bookings():
    booking_service.purge_archived_bookings(get_user_id())
    # the success message has always been sent under "error"; the frontend may rely on it.
    return jsonify({"error": "All deleted bookings have been removed successfully"}), 200


@bookings.route('/delete-deleted-booking/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_deleted_booking_by_id(id):
    booking_service.purge_archived_booking_by_id(get_user_id(), id)
    return jsonify({"message": "Deleted booking removed successfully"}), 200


@bookings.route('/delete-deleted-booking', methods=['DELETE'])
@jwt_required()
def delete_deleted_booking():
    data = load_json(ArchivedBookingDeleteSchema)
    booking_service.purge_archived_booking(get_user_id(), data['date'], data['property_name'])
    return jsonify({"message": "Deleted booking removed successfully"}), 200
