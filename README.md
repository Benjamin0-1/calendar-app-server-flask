Property Booking System 
Overview
The Property Booking System is a web application designed to facilitate property management and booking. It includes features for user authentication, property creation, booking management, and security measures to protect against brute force attacks and DDoS attacks.

Features
Authentication with JWTs: Uses JSON Web Tokens (JWTs) for secure authentication. Tokens are used to verify the identity of users accessing the system.

Brute Force Protection: Implements mechanisms to prevent brute force attacks on login endpoints. This includes rate limiting and CAPTCHA challenges after multiple failed login attempts.

DDoS Protection: Incorporates DDoS protection measures to mitigate potential denial of service attacks. This includes monitoring and rate limiting of incoming requests.

Email Confirmation: Requires email confirmation upon user registration to verify the validity of email addresses. This helps ensure that only legitimate users can access the system.

Property Management: Allows users to create and manage multiple properties. Each property can have details such as location, description, amenities, etc.

Booking System: Enables users to book different dates for their properties. Proper validations are in place to ensure data integrity, preventing overlapping bookings and ensuring accurate scheduling.

Technologies Used
Backend: Python with Flask framework
Database: PostgreSQL for data storage
Authentication: JWT tokens for secure user authentication
Frontend: ReactJs, Redux
Setup Instructions
Clone the repository:

bash
Copy code
git clone https://github.com/Benjamin0-1/calendar-app-server-flask.git
cd property-booking-system
Install dependencies:

bash
Copy code
pip install -r requirements.txt
Set up environment variables for database connection, JWT secret key, etc.:

bash
Copy code
export DATABASE_URL='your-database-url'
export SECRET_KEY='your-secret-key'
Initialize the database:

bash
Copy code
flask db init
flask db migrate
flask db upgrade
Run the application:

bash
Copy code
flask run
Access the application at http://localhost:5000 in your web browser.

API Documentation
For detailed API documentation and endpoints, refer to the API Documentation.

Contributing
Contributions are welcome! Please fork the repository and submit a pull request with your enhancements.

License
This project is licensed under the MIT License - see the LICENSE file for details.
