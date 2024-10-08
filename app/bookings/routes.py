from flask import request, jsonify
from app.models import BookedDate, User, Property, DeletedDate
from . import bookings
from app import db
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_jwt_extended.utils import decode_token
from datetime import datetime, timedelta
import time
from ..utils.get_user_id import get_user_id  # from app/utils.
import traceback


# things left to here: nothing (up to the first release, before parties).



# THIS IS THE ROUTE THAT CAN'T BE ACCESSED DUE TO CORS.
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
                "customerName": booking.customer_name,
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
        property_id = int(data.get('propertyId'))  
        customer_name = data.get('customerName')  
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


@bookings.route('/', methods=['PATCH'])
@jwt_required()
def update_booking():
    data = request.json
    property_id = data.get('propertyId')
    current_date = data.get('currentDate') # date to be updated inside of the specific propertyId it belongs to, it must exists for the specific property selected.
    customer_name = data.get('customerName')
    new_date = data.get('newDate')
    #customer_phone_number = data.get('customerPhoneNumber')

    current_user_id = get_user_id()

    if not property_id:
        return jsonify({"error": "Missing property id"}), 400
    
    if not current_date:
        return jsonify({"error": "Current date is required"}), 400

    # Check that the user owns the property they are trying to update
    property = Property.query.filter_by(id=property_id, user_id=current_user_id).first()
    if not property:
        return jsonify({"error": "You don't own this property"}), 400

    # Check if the booking exists
    booking = BookedDate.query.filter_by(property_id=property_id, date=current_date).first()
    if not booking:
        return jsonify({"error": "Booking to be updated doesn't exist."}), 404

    # Check if at least one parameter to be updated is provided
    if not customer_name and not new_date:
        return jsonify({"error": "Must provide at least one parameter to be updated"}), 400

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
    property_id = data.get('propertyId')
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
    property_name = data.get('propertyName')

    if not property_name:
        return jsonify({"error": "Missing propertyName in request data"}), 400

    jwt_token = request.headers.get('Authorization').split()[1] 

    try:
        current_user_id = get_user_id()
    except Exception as e:
        return jsonify({"error": "Invalid Json web token", "details": str(e)}), 500
    
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # case insensitive search for property name.
    property_exists = Property.query.filter(Property.property_name.ilike(property_name), Property.user_id == current_user_id).first()
    if property_exists:
        return jsonify({"error": f"Property: {property_name} already exists."}), 400
    
    new_property = Property(property_name=property_name, user_id=current_user_id)

    try:
        db.session.add(new_property)
        db.session.commit()

        return jsonify({
            "success": "Property created successfully",
            "property": {
                "id": new_property.id,
                "propertyName": new_property.property_name,
                "userId": new_property.user_id
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
@bookings.route('/user-properties')
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

@bookings.route('/view-deleted-bookings')
@jwt_required()
def view_deleted_bookings():
    current_user_id = get_user_id()
    
    deleted_bookings = DeletedDate.query.filter_by(user_id=current_user_id).all()

    if not deleted_bookings:
        return jsonify({"error": "No deleted bookings found"}), 404
    
    deleted_bookings_list = [booking.serialize() for booking in deleted_bookings]

    return jsonify({"deletedBookings": deleted_bookings_list})



@bookings.route('/delete-all-deleted-bookings', methods=['DELETE'])
@jwt_required()
def delete_all_deleted_bookings():
    current_user_id = get_user_id()

    try:
        deleted_bookings = DeletedDate.query.filter_by(user_id=current_user_id).all() # get the array

        if not deleted_bookings:
            return jsonify({"error": "No deleted bookings found for the current user"}), 404

        # check if in the array.
        for booking in deleted_bookings:
            db.session.delete(booking)

        db.session.commit()
        return jsonify({"error": "All deleted bookings have been removed successfully"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to delete all deleted bookings", "details": str(e)}), 500


@bookings.route('/delete-deleted-booking/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_deleted_booking_by_id(id):
    current_user_id = get_user_id()

    if not id:
        return jsonify({"error": "ID is required"}), 400

    try:
        deleted_booking = DeletedDate.query.filter_by(id=id, user_id=current_user_id).first()

        if not deleted_booking:
            return jsonify({"error": "No deleted booking found for the given ID"}), 404

        db.session.delete(deleted_booking)
        db.session.commit()

        return jsonify({"message": "Deleted booking removed successfully"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to delete the booking", "details": str(e)}), 500


@bookings.route('/delete-deleted-booking', methods=['DELETE'])
@jwt_required()
def delete_deleted_booking():
    data = request.get_json()
    date_str = data.get('date')
    #property_id = data.get('propertyId')
    property_name = data.get('propertyName') # this model uses property_name instead of property_id.

    if not date_str or not property_name:
        return jsonify({"error": "Date and property name is required."}), 400

    
    try:
        date = datetime.strptime(date_str, "%Y-%m-%d").date()  
    except ValueError:
        return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400

    current_user_id = get_user_id()

    try:
        deleted_booking = DeletedDate.query.filter_by(date=date, user_id=current_user_id, property_name=property_name).first()

        if not deleted_booking:
            return jsonify({"error": "No deleted booking found for the given date"}), 404

        db.session.delete(deleted_booking)
        db.session.commit()

        return jsonify({"message": "Deleted booking removed successfully"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to delete the booking", "details": str(e)}), 500
    
# new route to support detail.
@bookings.route('/property-details/<int:id>')
@jwt_required()
def property_details(id):
    current_user_id = get_user_id()

    property = Property.query.filter_by(id=id, user_id=current_user_id).first()

    if not property:
        return jsonify({"error": "Property not found"}), 404

    return jsonify(property.serialize())



# will add a pagination route, which will improve the performance of the app by reducing the amount of data sent to the client at once.
# it can be combined with GET /bookings .

# default must be return all of the bookings at once (no pagination).
@bookings.route('/filter-bookings', methods=['GET'])
@jwt_required()
def filter_bookings():
    query = BookedDate.query
    current_user_id = get_user_id()

    # Always filter by user_id to ensure they can't manipulate the query.
    query = query.filter(BookedDate.user_id == current_user_id)

    # Start constructing the query based on the parameters received dynamically.
    property_name = request.args.get('propertyName')
    if property_name:
        owns_property = Property.query.filter_by(property_name=property_name, user_id=current_user_id).first()
        if not owns_property:
            return jsonify({"error": "You don't own this property"}), 403
        query = query.join(Property).filter(Property.property_name.ilike(f'%{property_name}%'))

    date_str = request.args.get('date')
    if date_str:
        try:
            date = datetime.strptime(date_str, '%Y-%m-%d').date()
            query = query.filter(BookedDate.date == date)
        except ValueError:
            return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD.'}), 400

    customer_name = request.args.get('customerName')
    if customer_name:
        query = query.filter(BookedDate.customer_name.ilike(f'%{customer_name}%'))

    property_id = request.args.get('propertyId')
    if property_id:
        try:
            property_id = int(property_id)
            query = query.filter(BookedDate.property_id == property_id)
        except ValueError:
            return jsonify({"error": "Invalid property ID format."}), 400

    # Choose desc or asc 
    sort_order = request.args.get('sort_order')
    if sort_order == 'desc':
        query = query.order_by(BookedDate.date.desc())
    elif sort_order == 'asc':
        query = query.order_by(BookedDate.date.asc())
    else:
        query = query.order_by(BookedDate.date.desc())  # Default to most recent bookings first

    # Handle pagination only if parameters are provided
    page = request.args.get('page', type=int)
    per_page = request.args.get('perPage', type=int)

    if page and per_page:
        total_bookings = query.count()
        query = query.limit(per_page).offset((page - 1) * per_page)
        bookings = query.all()

        total_pages = (total_bookings + per_page - 1) // per_page  # Calculate total pages
        pagination_info = {
            'page': page,
            'per_page': per_page,
            'total_bookings': total_bookings,
            'total_pages': total_pages,
            'next_page': page + 1 if page * per_page < total_bookings else None,
            'prev_page': page - 1 if page > 1 else None
        }
    else:
        bookings = query.all()
        pagination_info = None

    results = []
    for booking in bookings:
        booking_data = booking.serialize()
        booking_data['propertyName'] = booking.property.property_name  # This will only include the name if applied to the query.
        results.append(booking_data)

    if len(results) == 0:
        return jsonify({"error": "No bookings found"}), 404

    response = {
        'results': results,
        'pagination': pagination_info
    }

    # Apply the default query if no filters are provided
    if not property_name and not date_str and not customer_name and not property_id:
        default_query = BookedDate.query.filter_by(user_id=current_user_id).all()
        default_results = []
        for booking in default_query:
            booking_data = booking.serialize()
            booking_data['propertyName'] = booking.property.property_name
            default_results.append(booking_data)
        return jsonify(default_results)

    return jsonify(response)






'''
@bookings.route('/filter-bookings')
@jwt_required()
def filter_bookings():
    query = BookedDate.query # get all bookings.

    current_user_id = get_user_id()

    # this will always filter by user_id, ensuring they can't manipulate the query.
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
# to this route I need to add a 'desc' parameter to sort the results by date in descending order. 
# it will be a toggle button in the frontend, so the user can see the most recent bookings first and vice versa.
'''
