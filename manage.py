from flask.cli import FlaskGroup
from app import app
from flask_migrate import init, migrate, upgrade
from app.models.user import User
from app.models.option import Option
from app.models.poll import Poll
cli = FlaskGroup(app)

# Add Flask-Migrate commands


@cli.command('db_init')
def db_init():
    init()


@cli.command('db_migrate')
def db_migrate():
    migrate()


@cli.command('db_upgrade')
def db_upgrade():
    upgrade()


if __name__ == '__main__':
    cli()
