from flask import request, jsonify
from app.models import BookedDate, User, Property, DeletedDate
from . import bookings
from app import db
from flask_jwt_extended import jwt_required, get_jwt_identity

@bookings.route('/', methods=['GET'])
@jwt_required()  # Ensure the user is authenticated
def view_user_bookings():
    current_user = get_jwt_identity()
    user = User.query.filter_by(email=current_user).first()
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
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

    # Get the current user's ID from the JWT token
    current_user_id = get_jwt_identity()

    try:
        current_user_id = int(current_user_id)  # Convert to integer if necessary
        property_id = int(data['property_id'])  # Convert property_id to integer
    except ValueError:
        return jsonify({"error": "Invalid user or property ID format"}), 400

    # Verify if the property belongs to the current user
    property = Property.query.filter_by(id=property_id, user_id=current_user_id).first()

    if not property:
        return jsonify({"error": "Property does not exist or does not belong to the current user"}), 404

    # Check if such date is already booked for this property by the same user
    existing_booking = BookedDate.query.filter_by(
        user_id=current_user_id,
        date=data['date'],
        property_id=property_id
    ).first()

    if existing_booking:
        return jsonify({"error": "Date already booked for this property by you"}), 400

    # Create a new booking
    new_booking = BookedDate(
        date=data['date'],
        customer_name=data['customer_name'],
        user_id=current_user_id,
        property_id=property_id
    )
    
    db.session.add(new_booking)
    db.session.commit()

    return jsonify({"success": "Booking created successfully", "booking": new_booking.serialize()}), 201



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
    current_user_id = get_jwt_identity()

    if not data['property_name']:
        return jsonify({"error": "missing data"}), 400

    #fix type error
    try:
        current_user_id = int(current_user_id)
    except ValueError:
        return jsonify({"error": "Invalid user id format"}), 400
    
    # .get defaults to get it by id.
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    new_property = Property(property_name=property_name, user_id=current_user_id)

    try:

        db.session.add(new_property)
        db.session.commit()

        return jsonify({
            "success": "Property created successfully",
            "property": {
                "id": new_property.id,
                "property_name": new_property.property_name,
                'user_id': new_property.user_id

            }
        }), 201

    except Exception as e:
        db.session.rollback() # not required anymore since it was never commited.
        return jsonify({"error": "Failed to create property", "details": str(e)}), 500
