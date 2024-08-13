from .. import db
from sqlalchemy import UniqueConstraint

class Provider(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    provider_uuid = db.Column(db.String(36), nullable=False)  # Unique identifier for the provider
    provider_name = db.Column(db.String(100), nullable=False)  # e.g., Google, Facebook

    # Relationship with the User model
    users = db.relationship('User', back_populates='provider', cascade="all, delete-orphan")

    # Uniqueness constraint to ensure no duplicate provider records for the same UUID and provider name
    __table_args__ = (
        UniqueConstraint('provider_name', 'provider_uuid', name='unique_provider'),
    )

    def serialize(self):
        return {
            'providerName': self.provider_name,
            'providerUuid': self.provider_uuid,
        }

