# Local utils file for bookings. 
# Could be later replaced for a utils folder inside of /app .

from flask_jwt_extended import decode_token
from flask import request

def get_user_id():
    # Extract the JWT token from the request headers
    jwt_token = request.headers.get('Authorization').split()[1]
    
    # Decode the token to get the payload
    decoded_token = decode_token(jwt_token)
    
    # Extract user ID from the decoded token
    current_user_id = decoded_token.get('id')
    
    return int(current_user_id) if current_user_id else None
