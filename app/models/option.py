from app import db
from sqlalchemy.orm import relationship
from app.models.many_models import option_votes


class Option(db.Model):
    __tablename__ = 'options'

    id = db.Column(db.Integer, primary_key=True)
    poll_id = db.Column(db.Integer, db.ForeignKey('polls.id'), nullable=False)
    creator_id = db.Column(
        db.Integer, db.ForeignKey('users.id'), nullable=False)
    movie_name = db.Column(db.String(255), nullable=False)
    imdb_url = db.Column(db.String(255))
    rotten_tomatoes_url = db.Column(db.String(255))
    stream_url = db.Column(db.String(255))

    poll = db.relationship('Poll', backref=db.backref('options', lazy=True))
    creator = db.relationship('User', backref=db.backref('options', lazy=True))
    users_voted = db.relationship(
        'User', secondary=option_votes, backref=db.backref('options_voted', lazy=True),
        overlaps="voted_options,voted_users",
    )

    def __init__(self, poll_id, creator_id, movie_name, imdb_url, rotten_tomatoes_url, stream_url):
        self.poll_id = poll_id
        self.creator_id = creator_id
        self.movie_name = movie_name
        self.imdb_url = imdb_url
        self.rotten_tomatoes_url = rotten_tomatoes_url
        self.stream_url = stream_url

    def save(self):
        db.session.add(self)
        db.session.commit()

    def get_vote_count(self):
        return len(self.voters)

    def serialize(self):
        return {
            'id': self.id,
            'poll': self.poll.url,
            'creator_id': self.creator_id,
            'movie_name': self.movie_name,
            'imdb_url': self.imdb_url,
            'rotten_tomatoes_url': self.rotten_tomatoes_url,
            'stream_url': self.stream_url
        }
