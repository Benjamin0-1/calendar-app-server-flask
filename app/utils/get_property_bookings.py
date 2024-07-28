# can be used in / GET bookings 

'''
def get_property_bookings(property_id):
    """
    Helper function to get bookings for a given property.
    """
    bookings = BookedDate.query.filter_by(property_id=property_id).all()
    bookings_list = []
    
    for booking in bookings:
        bookings_list.append({
            "customer_name": booking.customer_name,
            "date": booking.date.strftime("%a, %d %b %Y")  # Format date as desired
        })

    return bookings_list'''