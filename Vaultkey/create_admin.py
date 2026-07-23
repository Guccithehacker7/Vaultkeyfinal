from app import create_app, db
from app.models import User
from werkzeug.security import generate_password_hash
import os

app = create_app()
with app.app_context():
    u = User.query.filter_by(email='admin@gmail.com').first()
    if u:
        u.username = 'admin'
        u.email = 'admin@gmail.com'
        u.password_hash = generate_password_hash('admin')
        u.role = 'admin'
        print('updated existing admin user')
    else:
        u = User(
            username='admin',
            email='admin@gmail.com',
            password_hash=generate_password_hash('admin'),
            role='admin',
        )
        db.session.add(u)
        print('created admin user')
    db.session.commit()

try:
    os.remove(__file__)
except Exception:
    pass
