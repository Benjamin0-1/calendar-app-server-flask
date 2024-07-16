from flask import request, jsonify
from app.models import BookedDate, User, Property, DeletedDate
from . import bookings
from app import db
from flask_jwt_extended import jwt_required, get_jwt_identity, decode_token
from datetime import datetime, timedelta
import time

@bookings.route('/', methods=['GET'])
@jwt_required()  
def view_user_bookings():
    current_user = get_jwt_identity()
    user = User.query.filter_by(email=current_user).first()
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # we need to include the relation with Property, so that
    # the user can see all of the info properly:
    # each date booked and the property that booked date belongs to.
    # or the other way around would work very similarly.
    user_bookings = BookedDate.query.filter_by(user=user).all()

    if len(user_bookings) == 0:
        return jsonify({"noDatesFound": True}), 404
    
    # Example: Assuming you want to return a list of booked dates with their details
    bookings_list = []
    for booking in user_bookings:
        bookings_list.append({
            "date": booking.date,
            "customer_name": booking.customer_name,
            "property_id": booking.property_id
        })

    return jsonify(bookings_list)



# book a date
@bookings.route('/', methods=['POST'])
@jwt_required()  
def book_date():
    data = request.get_json()

    jwt_token = request.headers.get('Authorization').split()[1]

    try:
        jwt_payload = decode_token(jwt_token)
        current_user_id = jwt_payload.get('id')
        current_user_id = int(current_user_id)  
        property_id = int(data.get('property_id'))  
        customer_name = data.get('customer_name')  
        booking_date = datetime.strptime(data.get('date'), '%Y-%m-%d').date()
    except Exception as e:
        return jsonify({"error": "Invalid user or property ID format", "details": str(e)}), 400
    
    #make sure a date is not from the past.
    current_date = datetime.utcnow().date()
    if booking_date < current_date:
        return jsonify({"error": "Can't book a date from the past."}), 400

    # Check if customer_name is provided
    if not customer_name:
        return jsonify({"error": "Customer name is required"}), 400

    # Verify if the property belongs to the current user
    property = Property.query.filter_by(id=property_id, user_id=current_user_id).first()

    if not property:
        return jsonify({"error": "Property does not exist or does not belong to the current user"}), 404

    # Check if such date is already booked for this property by the same user
    existing_booking = BookedDate.query.filter_by(
        user_id=current_user_id,
        date=data.get('date'),
        property_id=property_id
    ).first()

    if existing_booking:
        return jsonify({"error": "Date already booked for this property by you"}), 400

    # Create a new booking
    new_booking = BookedDate(
        date=data.get('date'),
        customer_name=customer_name,
        user_id=current_user_id,
        property_id=property_id
    )

    try:
        db.session.add(new_booking)
        db.session.commit()

        return jsonify({"success": "Booking created successfully", "booking": new_booking.serialize()}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to create booking", "details": str(e)}), 500


# we can update a booking customer name, date, and that's it (for now).
@bookings.route('/', methods=['PUT'])
@jwt_required()
def update_booking():
    data = request.json
    id = data.get('id')  # ID of date to be updated, first check it exists.
    customer_name = data.get('customer_name')
    date = data.get('date')

    if not id:
        return jsonify({"message": "Missing date id"}), 400

    # Check that such date exists by its id
    booking = BookedDate.query.get(id)
    if not booking:
        return jsonify({"dateNotFound": "Date to be updated doesn't exist."}), 404

    # Check if at least one parameter to be updated is provided
    if not customer_name and not date:
        return jsonify({"missingData": "Must provide at least one parameter to be updated"}), 400
    
    # Update the booking with the provided data only.
    if customer_name:
        booking.customer_name = customer_name
    if date:
        booking.date = date

    try:
        db.session.commit()
        return jsonify({"message": "Booking updated successfully"})
    except Exception as e:
        #db.session.rollback()
        return jsonify({"error": "Failed to update booking", "details": str(e)}), 500

@bookings.route('/', methods=['DELETE'])
@jwt_required()
def delete_booking():
    data = request.json
    id = data.get('id')

    if not id:
        return jsonify({"missingId": True}), 400
    
    booking = BookedDate.query.get(id)
    if not booking:
        return jsonify({"dateNotFound": "Booking doesn't exist"}), 404
    
    try:
        # Copy
        deleted_booking = DeletedDate(
            customer_name=booking.customer_name,
            date=booking.date,
            property_id=booking.property_id,
            user_id=booking.user_id
         
        )
        db.session.add(deleted_booking)

        # Delete the booking from BookedDate model
        db.session.delete(booking)
        db.session.commit()

        return jsonify({"message": "Booking deleted successfully and archived in DeletedDate model"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to delete booking", "details": str(e)}), 500
    

@bookings.route('/create-property', methods=['POST'])
@jwt_required()
def create_property():
    data = request.get_json()
    property_name = data.get('property_name')

    if not property_name:
        return jsonify({"error": "Missing property_name in request data"}), 400

    jwt_token = request.headers.get('Authorization').split()[1] 

    try:
        jwt_payload = decode_token(jwt_token)
        current_user_id = jwt_payload.get('id')
        current_user_id = int(current_user_id) # avoid type error.
    except Exception as e:
        return jsonify({"error": "Invalid Json web token", "details": str(e)}), 500
    
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    property_exists = Property.query.filter_by(property_name=property_name).first()
    if property_exists:
        return jsonify({"error": f"Property: {property_name} already exists."}), 409
    
    new_property = Property(property_name=property_name, user_id=current_user_id)

    try:
        db.session.add(new_property)
        db.session.commit()

        return jsonify({
            "success": "Property created successfully",
            "property": {
                "id": new_property.id,
                "property_name": new_property.property_name,
                "user_id": new_property.user_id
            }
        }), 201
    
    except Exception as e:
        db.session.rollback() # not necessary, just in case.
        return jsonify({"error": "Failed to create property", "details": str(e)}), 500

    

# new route in which the user can see all of his properties.
