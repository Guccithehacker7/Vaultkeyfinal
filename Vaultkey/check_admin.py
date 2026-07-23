from app import create_app, db
from app.models import User

app = create_app()
with app.app_context():
    u = User.query.filter_by(email='admin@gmail.com').first()
    if u:
        print(f"FOUND: username={u.username} email={u.email} role={u.role}")
    else:
        print("NOT FOUND")
