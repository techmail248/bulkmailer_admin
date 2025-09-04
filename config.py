import os

class Config:
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'dev-secret')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///bulkmailer.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
    MAX_CONTENT_LENGTH = 25 * 1024 * 1024  # 25 MB
    FERNET_KEY = os.getenv('FERNET_KEY')
    APP_BASE_URL = os.getenv('APP_BASE_URL', 'http://localhost:5000')

    @staticmethod
    def init_app(app):
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
