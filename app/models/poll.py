from app import db
from app.models.user import User
from app.models.option import Option
from sqlalchemy.orm import relationship
from random import sample
import nltk

nltk.download('words')

word_list = nltk.corpus.words.words()


def generate_identifier_url():
    while True:
        random_words = sample(word_list, 4)
        identifier_url = '-'.join(random_words)

        # Check if the generated URL already exists in the database
        existing_poll = Poll.query.filter_by(url=identifier_url).first()
        if not existing_poll:
            return identifier_url


class Poll(db.Model):
    __tablename__ = 'polls'

    id = db.Column(db.Integer, primary_key=True)
    curtain_call = db.Column(db.String(255), nullable=False)
    url = db.Column(db.String(255), nullable=False,  unique=True, index=True)
    creator_id = db.Column(
        db.Integer, db.ForeignKey('users.id'), nullable=False)

    creator = db.relationship('User', backref=db.backref('polls', lazy=True))

    def __init__(self, curtain_call, creator_id):
        self.curtain_call = curtain_call
        self.url = generate_identifier_url()
        self.creator_id = creator_id

    def save(self):
        db.session.add(self)
        db.session.commit()

    def get_options(self):
        return Option.query.filter_by(poll_id=self.id).all()

    def serialize(self):
        return {
            'curtain_call': self.curtain_call,
            'url': self.url,
            'creator_id': self.creator_id,
            'options': [option.serialize() for option in self.options],
        }
