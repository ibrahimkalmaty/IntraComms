from flask_sqlalchemy import SQLAlchemy

# Single SQLAlchemy instance shared across all models.
# Import this into your Flask app and call db.init_app(app).
db = SQLAlchemy()
