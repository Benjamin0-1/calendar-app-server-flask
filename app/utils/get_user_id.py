from flask_jwt_extended import decode_token
from flask import request

def get_user_id():
 
    jwt_token = request.headers.get('Authorization').split()[1]
    

    decoded_token = decode_token(jwt_token)
    

    current_user_id = decoded_token.get('id')
    
    # convert to int if possible.
    return int(current_user_id) if current_user_id else None


    
