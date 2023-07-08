from app import db
option_votes = db.Table(
    'option_votes',
    db.Column('user_id', db.Integer, db.ForeignKey(
        'users.id'), primary_key=True),
    db.Column('option_id', db.Integer, db.ForeignKey(
        'options.id'), primary_key=True)
)
