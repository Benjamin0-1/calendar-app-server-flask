from flask import request, jsonify
from app.models import BookedDate, User, Property, DeletedDate
from . import bookings
from app import db
from flask_jwt_extended import jwt_required, get_jwt_identity, decode_token
from datetime import datetime, timedelta
import time
from .utils import get_user_id # remove this one later and replace it with the one below.
#from app.utils.get_user_id import get_user_id # <- this ONE.

# things left to here: nothing (up to the first release).

@bookings.route('/', methods=['GET'])
@jwt_required()  
def view_user_bookings():
    current_user_id = get_user_id() 
    
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404

    user_properties = Property.query.filter_by(user_id=current_user_id).all()

    if not user_properties:
        return jsonify({"error": "User has no properties"}), 404

    response_dict = {}
   
    for property in user_properties:
      
        bookings = BookedDate.query.filter_by(property_id=property.id).all() # all of the bookings asssociated to each user property.

        # now we have all of the bookings, if any.
        bookings_list = []  # going to be an array inside of the response.
        for booking in bookings:
            bookings_list.append({
                "customer_name": booking.customer_name,
                "date": booking.date.strftime("%a, %d %b %Y")  
            })

        # if anything at all got appended (pushed).
        if bookings_list:
            response_dict[property.property_name] = { # first time pushing to the dictionary.
                "id": property.id,
                "bookings": bookings_list # push all bookings instead of one.
            }
        else:
            response_dict[property.property_name] = { # property_name is the key, what goes below would be the "value".
                "id": property.id,
                "bookings": [],
                "message": "No dates booked for this property yet"
            }

    return jsonify(response_dict)






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
    current_date = data.get('current_date') # date to be updated, it must exists for the specific property selected.
    customer_name = data.get('customer_name')
    new_date = data.get('new_date')

    current_user_id = get_user_id()

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




# DeletedDate inside of /models/booking.py
@bookings.route('/', methods=['DELETE'])
@jwt_required()
def delete_booking():
    data = request.json
    property_id = data.get('property_id')
    date = data.get('date')

    # Extract user_id from JWT
    current_user_id = get_user_id()

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
        # DeletedDate needs to first be created.
        # Create a copy of the booking in the DeletedDate model
        deleted_booking = DeletedDate(
            customer_name=booking.customer_name,
            date=booking.date,
            property_name=property.property_name,
            user_id=current_user_id
            #user_email #<=
        )
        db.session.add(deleted_booking)

        # Delete the booking from the BookedDate model
        db.session.delete(booking)
        db.session.commit()

        return jsonify({"message": "Booking deleted successfully and archived in DeletedDate model"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to delete booking", "details": str(e)}), 500


    
# create a property.
@bookings.route('/create-property', methods=['POST'])
@jwt_required()
def create_property():
    data = request.get_json()
    property_name = data.get('property_name')

    if not property_name:
        return jsonify({"error": "Missing property_name in request data"}), 400

    jwt_token = request.headers.get('Authorization').split()[1] 

    try:
        current_user_id = get_user_id()
    except Exception as e:
        return jsonify({"error": "Invalid Json web token", "details": str(e)}), 500
    
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # fix 
    property_exists = Property.query.filter_by(property_name=property_name, user_id=current_user_id).first()
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

# delete a property.
@bookings.route('/delete-property', methods=['DELETE'])
@jwt_required()
def delete_property():
    data = request.get_json()
    property_id = data.get('property_id')

    if not property_id:
        return jsonify({"error": "Property ID is required"}), 400

   
    current_user_id = get_user_id()

    # Check that the user owns the property they are trying to delete
    property = Property.query.filter_by(id=property_id, user_id=current_user_id).first()
    if not property:
        return jsonify({"error": "You don't own this property"}), 403

  
    if not property:
        return jsonify({"error": "Property not found"}), 404

    try:
        bookings = BookedDate.query.filter_by(property_id=property_id).all()
        for booking in bookings:
            deleted_booking = DeletedDate(
                customer_name=booking.customer_name,
                date=booking.date,
                property_name=property.property_name,
                user_id=current_user_id
            )
            db.session.add(deleted_booking)
            db.session.delete(booking)
        
        # Delete the property
        db.session.delete(property)
        db.session.commit()

        return jsonify({"message": "Property deleted successfully and associated bookings archived in DeletedDate model"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to delete property", "details": str(e)}), 500



# new route in which the user can see all of his properties.
@bookings.route('/user-properties', methods=['GET'])
@jwt_required()
def user_properties():
    current_user_id = get_user_id()

    # Query for the user's properties
    user_properties = Property.query.filter_by(user_id=current_user_id).all()
    
    if not user_properties:
        return jsonify({"error": "You have no properties yet."}), 404
    
    user_properties_list = []

    # Serialize each property
    for property in user_properties:
        user_properties_list.append({
            "id": property.id,
            "property_name": property.property_name
        })

    return jsonify({"Your properties": user_properties_list})

#DELETED BOOKNGS:

@bookings.route('/view-deleted-bookings', methods=['GET'])
@jwt_required()
def view_deleted_bookings():
    current_user_id = get_user_id()
    
    deleted_bookings = DeletedDate.query.filter_by(user_id=current_user_id).all()

    if not deleted_bookings:
        return jsonify({"error": "No deleted bookings found"}), 404
    
    deleted_bookings_list = [booking.serialize() for booking in deleted_bookings]

    return jsonify({"deleted_bookings": deleted_bookings_list})



@bookings.route('/delete-all-deleted-bookings', methods=['DELETE'])
@jwt_required()
def delete_all_deleted_bookings():
    current_user_id = get_user_id()

    try:
        deleted_bookings = DeletedDate.query.filter_by(user_id=current_user_id).all() # get the array

        if not deleted_bookings:
            return jsonify({"message": "No deleted bookings found for the current user"}), 404

        # check if in the array.
        for booking in deleted_bookings:
            db.session.delete(booking)

        db.session.commit()
        return jsonify({"message": "All deleted bookings have been removed successfully"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to delete all deleted bookings", "details": str(e)}), 500

@bookings.route('/delete-deleted-booking', methods=['DELETE'])
@jwt_required()
def delete_deleted_booking():
    data = request.get_json()
    date_str = data.get('date')

    if not date_str:
        return jsonify({"error": "Date is required"}), 400

    
    try:
        date = datetime.strptime(date_str, "%Y_%d_%m").date()
    except ValueError:
        return jsonify({"error": "Invalid date format. Use YYYY_DD_MM"}), 400

    current_user_id = get_user_id()

    try:
        deleted_booking = DeletedDate.query.filter_by(date=date, user_id=current_user_id).first()

        if not deleted_booking:
            return jsonify({"error": "No deleted booking found for the given date"}), 404

        db.session.delete(deleted_booking)
        db.session.commit()
        return jsonify({"message": "Deleted booking removed successfully"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to delete the booking", "details": str(e)}), 500


# dynamic filtering.
@bookings.route('/filter-bookings')
@jwt_required()
def filter_bookings():
    query = BookedDate.query

   
    current_user_id = get_user_id()

    # this always filter by user_id, ensuring they can't manipulate the query.
    query = query.filter(BookedDate.user_id == current_user_id)

    property_name = request.args.get('property_name')
    if property_name:
        query = query.join(Property).filter(Property.property_name.ilike(f'%{property_name}%'))
    
    date_str = request.args.get('date')
    if date_str:
        try:
            date = datetime.strptime(date_str, '%Y-%m-%d').date()
            query = query.filter(BookedDate.date == date)
        except ValueError:
            return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD.'}), 400

    customer_name = request.args.get('customer_name')
    if customer_name:
        query = query.filter(BookedDate.customer_name.ilike(f'%{customer_name}%'))
    
    property_id = request.args.get('property_id')
    if property_id:
        try:
            property_id = int(property_id)
            query = query.filter(BookedDate.property_id == property_id)
        except ValueError:
            return jsonify({'error': 'Invalid property ID format.'}), 400

    bookings = query.all()
    results = [booking.serialize() for booking in bookings]

    if len(results) == 0:
        return jsonify({"error": "no bookings found"}), 404

    return jsonify(results)

