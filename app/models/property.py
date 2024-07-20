from .. import db
from sqlalchemy import UniqueConstraint

class Property(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    property_name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    owner = db.relationship('User', back_populates='properties')
    booked_dates = db.relationship('BookedDate', back_populates='property')

    __table_args__ = (UniqueConstraint('property_name', 'user_id', name='unique_property_per_user'),)

    def __repr__(self):
        return f'<Property {self.id}, {self.property_name}>'

    def serialize(self):
        return {
            "id": self.id,
            "property_name": self.property_name,
            "user_id": self.user_id,
            'booked_dates': [booked_date.serialize() for booked_date in self.booked_dates]
        }

