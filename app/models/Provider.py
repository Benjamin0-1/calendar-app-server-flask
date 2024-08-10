from .. import db
from sqlalchemy import UniqueConstraint, CheckConstraint

# this is the provider model, the idea here is that we can identify a user's third party provider, like google, facebook, etc.
# here we will check things such as :
# - the provider name (google, facebook, etc).
# the user_id is the foreign key, so we can identify the user that is using the provider.
# the user (if third party user, which we can check if they have a record here) can only belong to one provider (per email).
# this is a one to one relationship.
# Very important: If a user registered locally, they cannot have a provider record, and vice versa.

class Provider(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    provider_name = db.Column(db.String(100), nullable=False)  # Google, Facebook, etc.
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)

    # Relationships
    user = db.relationship('User', back_populates='provider')

    def serialize(self):
        return {
            'providerName': self.provider_name,
            'userId': self.user_id,
            'userEmail': self.user.email,  # This assumes a relationship with the User model
        }


