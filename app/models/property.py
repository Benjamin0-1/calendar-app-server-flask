from .. import db

class Property(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    property_name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    owner = db.relationship('User', back_populates='properties')
    booked_dates = db.relationship('BookedDate', back_populates='property')

