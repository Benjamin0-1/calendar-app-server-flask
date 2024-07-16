from .. import db

class BookedDate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, unique=True, nullable=False)
    customer_name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    property_id = db.Column(db.Integer, db.ForeignKey('property.id'))

    user = db.relationship('User', back_populates='booked_dates')
    property = db.relationship('Property', back_populates='booked_dates')

    def __repr__(self):
        return f'<BookedDate {self.id}>'

    def serialize(self):
        return {
            "id": self.id,
            "date": self.date.isoformat(),
            "customer_name": self.customer_name,
            "property_id": self.property_id
        }


class DeletedDate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    customer_name = db.Column(db.String(100), nullable=False)
