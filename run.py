from app import app, db
from flask_migrate import Migrate
import ssl


if __name__ == '__main__':
    # context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    # context.load_cert_chain("cert.pem", "key.pem")
    migrate = Migrate(app, db)
    app.run(host='0.0.0.0', port=5000)  # , ssl_context=context)
