from .database import SessionLocal
from .models import User
from .auth import hash_password

db = SessionLocal()

admin = db.query(User).filter(User.username == "admin").first()
if not admin:
    admin = User(
        username="admin",
        password_hash=hash_password("Admin123!"),
        role="admin"
    )
    db.add(admin)
    db.commit()
    print("Admin user created.")
else:
    print("Admin user already exists.")
