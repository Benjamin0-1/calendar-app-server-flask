# Multi Property Booking System

client URL: https://github.com/Benjamin0-1/calendar-app-client-flask

## Overview

The Property Booking System is a web application designed to streamline property management and booking. It includes features for user authentication, property creation, booking management, and much more.

## Features

- **JWT Authentication**: Uses JSON Web Tokens (JWTs) for secure user authentication, ensuring that only authorized users can access the system.
- **Brute Force Protection**: Implements mechanisms to prevent brute force attacks on login endpoints.
- **Email Confirmation**: Requires email verification upon user registration to confirm the validity of email addresses and ensure legitimate access.
- **Property Management**: Allows users to create and manage multiple properties, including details such as location, description, and amenities.
- **Booking System**: Enables users to book different dates for their properties with proper validations to prevent overlapping bookings and ensure accurate scheduling.
- **Alert email**: In case a suspicious login is detected, the user will receive an email being informed of such action, along with other data.

## Technologies Used

- **Backend**: Python with Flask and SQLAlchemy
- **Database**: PostgreSQL
- **Authentication**: JWT tokens for secure user access
- **Frontend**: React.js with MUI5

## Setup Instructions

   ```bash
   git clone https://github.com/Benjamin0-1/calendar-app-server-flask.git
   cd calendar-app-server-flask
   pip3 install -r requirements.txt
   python3 run.py

