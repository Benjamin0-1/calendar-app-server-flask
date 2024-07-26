from .. import db
from sqlalchemy import UniqueConstraint, CheckConstraint

class BookedDate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, unique=False, nullable=False) 
    customer_name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    property_id = db.Column(db.Integer, db.ForeignKey('property.id'))
   
    __table_args__ = (
        UniqueConstraint('date', 'property_id', name='unique_date_per_property'),
        CheckConstraint('date >= CURRENT_DATE', name='check_date_future_or_present')
    ) 

    user = db.relationship('User', back_populates='booked_dates')
    property = db.relationship('Property', back_populates='booked_dates')

    def __repr__(self):
        return f'<BookedDate {self.id}>'

    def serialize(self):
        return {
            'id': self.id,
            'date': self.date.isoformat(),
            'customer_name': self.customer_name,
            'property_id': self.property_id,
            'user_id': self.user_id
        }

# we also need the propertyname, not as a relation but as a copy of it.
class DeletedDate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    customer_name = db.Column(db.String(100), nullable=False)
    property_name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  

    def serialize(self):
        return {
            'id': self.id,
            "date": self.date.strftime("%a, %d %b %Y"),
            'customer_name': self.customer_name,
            'property_name': self.property_name
        }

    