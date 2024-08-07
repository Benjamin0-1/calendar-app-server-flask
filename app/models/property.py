from .. import db
from sqlalchemy import UniqueConstraint

class Property(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    property_name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    # each property should have default image just to make it look better in the frontend.
    # default_image = db.Column(db.String(100), nullable=True, default='https://i.ytimg.com/vi/gVwV_vnS_rg/maxresdefault.jpg')

    owner = db.relationship('User', back_populates='properties')
    booked_dates = db.relationship('BookedDate', back_populates='property')

    __table_args__ = (UniqueConstraint('property_name', 'user_id', name='unique_property_per_user'),)

    def __repr__(self):
        return f'<Property {self.id}, {self.property_name}>'

    # moved to camel case.
    def serialize(self):
        return {
            "id": self.id,
            "propertyName": self.property_name,
            "userId": self.user_id,
            'bookedDates': [booked_date.serialize() for booked_date in self.booked_dates]
        }

