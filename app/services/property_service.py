from app.errors import error, failed, respond_on_failure
from app.extensions import db
from app.models import BookedDate, Property, User
from app.schemas.bookings import CreatedPropertySchema, PropertySummarySchema
from app.services.booking_service import archive_booking


def user_properties(user_id):
    properties = Property.query.filter_by(user_id=user_id).all()
    if not properties:
        raise error("You have no properties yet.", 404)
    return PropertySummarySchema(many=True).dump(properties)


def property_details(user_id, property_id):
    property = Property.query.filter_by(id=property_id, user_id=user_id).first()
    if not property:
        raise error("Property not found", 404)
    return property.serialize()


def create_property(user_id, property_name):
    if not db.session.get(User, user_id):
        raise error("User not found", 404)

    # case insensitive search for property name.
    if Property.query.filter(Property.property_name.ilike(property_name), Property.user_id == user_id).first():
        raise error(f"Property: {property_name} already exists.", 400)

    new_property = Property(property_name=property_name, user_id=user_id)
    with respond_on_failure(failed("Failed to create property")):
        db.session.add(new_property)
        db.session.commit()
    return CreatedPropertySchema().dump(new_property)


def delete_property(user_id, property_id):
    """Delete the property, archiving its bookings as deleted bookings."""
    property = Property.query.filter_by(id=property_id, user_id=user_id).first()
    if not property:
        raise error("You don't own this property", 403)

    with respond_on_failure(failed("Failed to delete property")):
        for booking in BookedDate.query.filter_by(property_id=property_id).all():
            archive_booking(booking, property.property_name, user_id)
        db.session.delete(property)
        db.session.commit()
