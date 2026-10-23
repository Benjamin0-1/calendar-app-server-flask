from flask import jsonify
from . import main

@main.route('/')
def index():
    return jsonify("This is the root URL of the server.")
