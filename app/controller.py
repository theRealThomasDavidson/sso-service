from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models.user import User
from app.models.poll import Poll
from app.models.option import Option
from app import db

app_bp = Blueprint('app', __name__)


@app_bp.route('/ping', methods=['GET'])
@jwt_required()
def ping():
    return jsonify({'message': 'Hello'})


@app_bp.route('/polls', methods=['GET'])
@jwt_required()
def get_polls():
    polls = Poll.query.all()
    return jsonify([poll.serialize() for poll in polls]), 200


@app_bp.route('/polls', methods=['POST'])
@jwt_required()
def create_poll():
    data = request.get_json()
    curtain_call = data.get('curtain_call')
    creator_id = get_jwt_identity()

    # Create a new poll
    poll = Poll(curtain_call=curtain_call, creator_id=creator_id)
    poll.save()

    # Add options to the poll
    options = data.get('options', [])
    for option_data in options:
        movie_name = option_data.get('movie_name')
        imdb_url = option_data.get('imdb_url')
        rotten_tomatoes_url = option_data.get('rotten_tomatoes_url')
        stream_url = option_data.get('stream_url')

        option = Option(
            poll_id=poll.id,
            creator_id=creator_id,
            movie_name=movie_name,
            imdb_url=imdb_url,
            rotten_tomatoes_url=rotten_tomatoes_url,
            stream_url=stream_url
        )
        option.save()

    return jsonify(poll.serialize()), 201


@app_bp.route('/polls/<url>', methods=['GET'])
@jwt_required()
def get_poll(url):
    poll = Poll.query.filter_by(url=url).first()
    if not poll:
        return jsonify({'error': 'Poll not found'}), 404

    return jsonify(poll.serialize()), 200


@app_bp.route('/polls/<url>', methods=['PUT'])
@jwt_required()
def update_poll(url):
    poll = Poll.query.filter_by(url=url).first()
    if not poll:
        return jsonify({'error': 'Poll not found'}), 404

    data = request.get_json()
    curtain_call = data.get('curtain_call')

    poll.curtain_call = curtain_call

    db.session.commit()

    return jsonify(poll.serialize()), 200


@app_bp.route('/polls/<url>', methods=['DELETE'])
@jwt_required()
def delete_poll(url):
    poll = Poll.query.filter_by(url=url).first()
    if not poll:
        return jsonify({'error': 'Poll not found'}), 404

    db.session.delete(poll)
    db.session.commit()

    return '', 204


@app_bp.route('/polls/vote/<url>', methods=['POST'])
@jwt_required()
def vote_on_poll(url):
    poll = Poll.query.filter_by(url=url).first()
    if not poll:
        return jsonify({'error': 'Poll not found'}), 404

    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()
    option_id = data.get('option_id')

    option = Option.query.get(option_id)
    if not option:
        return jsonify({'error': 'Option not found'}), 404

    if option.poll_id != poll.id:
        return jsonify({'error': 'Option not found'}), 404

    if user in option.voters:
        option.voters.remove(user)
        db.session.commit()
        return jsonify({'message': 'Vote removed successfully'}), 200

    option.voters.append(user)
    db.session.commit()

    return jsonify({'message': 'Vote added successfully'}), 200


@app_bp.route('/polls/<poll_url>/options', methods=['POST'])
@jwt_required()
def create_option(poll_url):
    poll = Poll.query.filter_by(url=poll_url).first()
    if not poll:
        return jsonify({'error': 'Poll not found'}), 404

    data = request.get_json()
    if isinstance(data, list):
        # Create multiple options from a list
        options = []
        for item in data:
            movie_name = item.get('movie_name')
            imdb_url = item.get('imdb_url')
            rotten_tomatoes_url = item.get('rotten_tomatoes_url')
            stream_url = item.get('stream_url')

            option = Option(
                poll_id=poll.id,
                creator_id=get_jwt_identity(),
                movie_name=movie_name,
                imdb_url=imdb_url,
                rotten_tomatoes_url=rotten_tomatoes_url,
                stream_url=stream_url
            )
            option.save()
            options.append(option)
        return jsonify([option.serialize() for option in options]), 201

    elif isinstance(data, dict):
        # Create a single option
        movie_name = data.get('movie_name')
        imdb_url = data.get('imdb_url')
        rotten_tomatoes_url = data.get('rotten_tomatoes_url')
        stream_url = data.get('stream_url')

        option = Option(
            poll_id=poll.id,
            creator_id=get_jwt_identity(),
            movie_name=movie_name,
            imdb_url=imdb_url,
            rotten_tomatoes_url=rotten_tomatoes_url,
            stream_url=stream_url
        )
        option.save()
        return jsonify(option.serialize()), 201

    return jsonify({'error': 'Invalid request body'}), 400


@app_bp.route('/polls/<poll_url>/options/<int:option_id>', methods=['GET'])
@jwt_required()
def get_option(poll_url, option_id):
    poll = Poll.query.filter_by(url=poll_url).first()
    if not poll:
        return jsonify({'error': 'Poll not found'}), 404

    option = Option.query.get(option_id)
    if not option or option.poll_id != poll.id:
        return jsonify({'error': 'Option not found'}), 404

    return jsonify(option.serialize()), 200


@app_bp.route('/polls/<poll_url>/options/<int:option_id>', methods=['PUT'])
@jwt_required()
def update_option(poll_url, option_id):
    poll = Poll.query.filter_by(url=poll_url).first()
    if not poll:
        return jsonify({'error': 'Poll not found'}), 404

    option = Option.query.get(option_id)
    if not option or option.poll_id != poll.id:
        return jsonify({'error': 'Option not found'}), 404

    data = request.get_json()
    option_text = data.get('option_text')
    imdb_url = data.get('imdb_url')
    rotten_tomatoes_url = data.get('rotten_tomatoes_url')
    stream_url = data.get('stream_url')

    option.option_text = option_text
    option.imdb_url = imdb_url
    option.rotten_tomatoes_url = rotten_tomatoes_url
    option.stream_url = stream_url

    db.session.commit()

    return jsonify(option.serialize()), 200


@app_bp.route('/polls/<poll_url>/options/<int:option_id>', methods=['DELETE'])
@jwt_required()
def delete_option(poll_url, option_id):
    poll = Poll.query.filter_by(url=poll_url).first()
    if not poll:
        return jsonify({'error': 'Poll not found'}), 404

    option = Option.query.get(option_id)
    if not option or option.poll_id != poll.id:
        return jsonify({'error': 'Option not found'}), 404

    db.session.delete(option)
    db.session.commit()

    return '', 204
