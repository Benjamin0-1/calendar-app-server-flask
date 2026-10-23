from datetime import datetime

from app.errors import error, failed, respond_on_failure
from app.extensions import db
from app.models import BookedDate, DeletedDate, Property, User
from app.schemas.base import parse_iso_date
from app.schemas.bookings import BookingSummarySchema


def _owned_property(property_id, user_id, status):
    property = Property.query.filter_by(id=property_id, user_id=user_id).first()
    if not property:
        raise error("You don't own this property", status)
    return property


def archive_booking(booking, property_name, user_id):
    """Move a booking to the deleted bookings archive; the caller commits."""
    db.session.add(DeletedDate(
        customer_name=booking.customer_name,
        date=booking.date,
        property_name=property_name,
        user_id=user_id,
    ))
    db.session.delete(booking)


# ---- bookings ----

def bookings_by_property(user_id):
    if not db.session.get(User, user_id):
        raise error("User not found", 404)

    user_properties = Property.query.filter_by(user_id=user_id).all()
    if not user_properties:
        raise error("User has no properties", 404)

    summary = BookingSummarySchema(many=True)
    response = {}
    for property in user_properties:
        bookings = summary.dump(BookedDate.query.filter_by(property_id=property.id).all())
        response[property.property_name] = {"id": property.id, "bookings": bookings}
        if not bookings:
            response[property.property_name]["message"] = "No dates booked for this property yet"
    return response


def create_booking(user_id, property_id, date, customer_name):
    property = Property.query.filter_by(id=property_id, user_id=user_id).first()
    if not property:
        raise error("Property does not exist or does not belong to the current user", 404)

    if BookedDate.query.filter_by(user_id=user_id, date=date, property_id=property_id).first():
        raise error("Date already booked for this property by you", 400)

    new_booking = BookedDate(date=date, customer_name=customer_name, user_id=user_id, property_id=property_id)
    with respond_on_failure(failed("Failed to create booking")):
        db.session.add(new_booking)
        db.session.commit()
    return new_booking.serialize()


def update_booking(user_id, property_id, current_date, customer_name=None, new_date=None):
    _owned_property(property_id, user_id, 400)

    booking = BookedDate.query.filter_by(property_id=property_id, date=current_date).first()
    if not booking:
        raise error("Booking to be updated doesn't exist.", 404)

    if not customer_name and not new_date:
        raise error("Must provide at least one parameter to be updated", 400)

    if new_date:
        try:
            new_date = parse_iso_date(new_date)
        except ValueError:
            raise error("Invalid date format. Use YYYY-MM-DD.", 400)
        if new_date < datetime.utcnow().date():
            raise error("New date cannot be from the past.", 400)
        booking.date = new_date

    if customer_name:
        booking.customer_name = customer_name

    with respond_on_failure(failed("Failed to update booking")):
        db.session.commit()


def delete_booking(user_id, property_id, date):
    property = _owned_property(property_id, user_id, 403)

    booking = BookedDate.query.filter_by(property_id=property_id, date=date).first()
    if not booking:
        raise error("Booking not found", 404)

    with respond_on_failure(failed("Failed to delete booking")):
        archive_booking(booking, property.property_name, user_id)
        db.session.commit()


def filter_bookings(user_id, property_name=None, date=None, customer_name=None, property_id=None,
                    sort_order=None, page=None, per_page=None):
    # Always filter by user_id to ensure they can't manipulate the query.
    query = BookedDate.query.filter(BookedDate.user_id == user_id)

    if property_name:
        if not Property.query.filter_by(property_name=property_name, user_id=user_id).first():
            raise error("You don't own this property", 403)
        query = query.join(Property).filter(Property.property_name.ilike(f'%{property_name}%'))

    if date:
        try:
            query = query.filter(BookedDate.date == parse_iso_date(date))
        except ValueError:
            raise error('Invalid date format. Use YYYY-MM-DD.', 400)

    if customer_name:
        query = query.filter(BookedDate.customer_name.ilike(f'%{customer_name}%'))

    if property_id:
        try:
            property_id = int(property_id)
        except ValueError:
            raise error("Invalid property ID format.", 400)
        query = query.filter(BookedDate.property_id == property_id)

    if sort_order == 'asc':
        query = query.order_by(BookedDate.date.asc())
    else:
        query = query.order_by(BookedDate.date.desc())  # Default to most recent bookings first

    # paginate only when both parameters are provided.
    pagination = None
    if page and per_page:
        total_bookings = query.count()
        query = query.limit(per_page).offset((page - 1) * per_page)
        pagination = {
            'page': page,
            'per_page': per_page,
            'total_bookings': total_bookings,
            'total_pages': (total_bookings + per_page - 1) // per_page,
            'next_page': page + 1 if page * per_page < total_bookings else None,
            'prev_page': page - 1 if page > 1 else None,
        }

    results = [_with_property_name(booking) for booking in query.all()]
    if not results:
        raise error("No bookings found", 404)

    # without filters, every booking is returned as a plain list, in insertion order and unpaginated.
    if not property_name and not date and not customer_name and not property_id:
        return [_with_property_name(booking) for booking in BookedDate.query.filter_by(user_id=user_id).all()]

    return {'results': results, 'pagination': pagination}


def _with_property_name(booking):
    return {**booking.serialize(), 'propertyName': booking.property.property_name}


# ---- deleted (archived) bookings ----

def archived_bookings(user_id):
    deleted_bookings = DeletedDate.query.filter_by(user_id=user_id).all()
    if not deleted_bookings:
        raise error("No deleted bookings found", 404)
    return [booking.serialize() for booking in deleted_bookings]


def purge_archived_bookings(user_id):
    with respond_on_failure(failed("Failed to delete all deleted bookings")):
        deleted_bookings = DeletedDate.query.filter_by(user_id=user_id).all()
        if not deleted_bookings:
            raise error("No deleted bookings found for the current user", 404)

        for booking in deleted_bookings:
            db.session.delete(booking)
        db.session.commit()


def purge_archived_booking_by_id(user_id, deleted_booking_id):
    if not deleted_booking_id:
        raise error("ID is required", 400)

    with respond_on_failure(failed("Failed to delete the booking")):
        deleted_booking = DeletedDate.query.filter_by(id=deleted_booking_id, user_id=user_id).first()
        if not deleted_booking:
            raise error("No deleted booking found for the given ID", 404)

        db.session.delete(deleted_booking)
        db.session.commit()


def purge_archived_booking(user_id, date, property_name):
    with respond_on_failure(failed("Failed to delete the booking")):
        deleted_booking = DeletedDate.query.filter_by(date=date, user_id=user_id, property_name=property_name).first()
        if not deleted_booking:
            raise error("No deleted booking found for the given date", 404)

        db.session.delete(deleted_booking)
        db.session.commit()
