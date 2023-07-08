from app import db
from app.models.many_models import option_votes


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    salt = db.Column(db.String(255), nullable=False)
    voted_options = db.relationship(
        'Option',
        secondary=option_votes,
        backref=db.backref('voted_users', lazy=True),
        overlaps="voted_options,voted_users"
    )

    def __init__(self, username, password, salt):
        self.username = username
        self.password = password
        self.salt = salt

    def save(self):
        db.session.add(self)
        db.session.commit()

    def get_polls(self):
        return Poll.query.filter_by(creator_id=self.id).all()
