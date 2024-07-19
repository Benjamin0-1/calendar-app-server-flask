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
    jwt_token = request.headers.get('Authorization').split()[1]
    jwt_payload = decode_token(jwt_token)
    current_user_id = jwt_payload.get('id')
    
    # Get the user by ID
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404

    user_properties = Property.query.filter_by(user_id=current_user_id).all()

    if not user_properties:
        return jsonify({"error": "User has no properties"}), 404

    # Prepare the response dictionary
    response_dict = {}

    # Iterate over each property to fetch bookings
    for property in user_properties:
        # Query bookings for the current property
        bookings = BookedDate.query.filter_by(property_id=property.id).all()

        # Prepare bookings list for the current property
        bookings_list = []
        for booking in bookings:
            bookings_list.append({
                "customer_name": booking.customer_name,
                "date": booking.date.strftime("%a, %d %b %Y")  # Format date as desired
            })

        # Add property details and bookings to response dictionary
        if bookings_list:
            response_dict[property.property_name] = {
                "id": property.id,
                "bookings": bookings_list
            }
        else:
            response_dict[property.property_name] = {
                "id": property.id,
                "bookings": [],
                "message": "No dates booked for this property yet"
            }

    return jsonify(response_dict)





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


@bookings.route('/', methods=['PUT'])
@jwt_required()
def update_booking():
    data = request.json
    property_id = data.get('property_id')
    current_date = data.get('current_date')
    customer_name = data.get('customer_name')
    new_date = data.get('new_date')

    # Extract user_id from JWT
    jwt_token = request.headers.get('Authorization').split()[1]
    decoded_token = decode_token(jwt_token)
    current_user_id = decoded_token.get('id')

    if not property_id or not current_date:
        return jsonify({"message": "Missing property id or current date"}), 400

    # Check that the user owns the property they are trying to update
    property = Property.query.filter_by(id=property_id, user_id=current_user_id).first()
    if not property:
        return jsonify({"error": "You don't own this property"}), 400

    # Check if the booking exists
    booking = BookedDate.query.filter_by(property_id=property_id, date=current_date).first()
    if not booking:
        return jsonify({"dateNotFound": "Booking to be updated doesn't exist."}), 404

    # Check if at least one parameter to be updated is provided
    if not customer_name and not new_date:
        return jsonify({"missingData": "Must provide at least one parameter to be updated"}), 400

    # Validate and format new_date if provided
    if new_date: # if provided.
        try:
            new_date_format = datetime.strptime(new_date, '%Y-%m-%d').date()
        except ValueError:
            return jsonify({"error": "Invalid date format. Use YYYY-MM-DD."}), 400
        
        # Ensure the new_date is not in the past
        today_date = datetime.utcnow().date()
        if new_date_format < today_date:
            return jsonify({"error": "New date cannot be from the past."}), 400
        
        # Update the booking date
        booking.date = new_date_format

    # Update customer name if provided
    if customer_name:
        booking.customer_name = customer_name

    try:
        db.session.commit()
        return jsonify({"message": "Booking updated successfully"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to update booking", "details": str(e)}), 500




# this need to be FINISHED. <=
@bookings.route('/', methods=['DELETE'])
@jwt_required()
def delete_booking():
    data = request.json
    property_id = data.get('property_id')
    date = data.get('date')

    # Extract user_id from JWT
    jwt_token = request.headers.get('Authorization').split()[1]
    decoded_token = decode_token(jwt_token)
    current_user_id = decoded_token.get('id')

    if not property_id or not date:
        return jsonify({"error": "Both property ID and date are required"}), 400

    # Check that the user owns the property they are trying to delete a booking from
    property = Property.query.filter_by(id=property_id, user_id=current_user_id).first()
    if not property:
        return jsonify({"error": "You don't own this property"}), 403

    # Check if the booking exists
    booking = BookedDate.query.filter_by(property_id=property_id, date=date).first()
    if not booking:
        return jsonify({"error": "Booking not found"}), 404

    try:
        # Create a copy of the booking in the DeletedDate model
        deleted_booking = DeletedDate(
            customer_name=booking.customer_name,
            date=booking.date,
            property_id=booking.property_id,
            user_id=booking.user_id
        )
        db.session.add(deleted_booking)

        # Delete the booking from the BookedDate model
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


# new route to see all of the deleted bookings/dates.
