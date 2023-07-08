from app import db


class RevokedToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), unique=True, nullable=False)

    def __init__(self, jti):
        self.jti = jti

    @classmethod
    def is_jti_blacklisted(cls, jti):
        return bool(cls.query.filter_by(jti=jti).first())
