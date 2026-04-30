from phishing_backend.database import init_db, SessionLocal
from phishing_backend.models import User
from phishing_backend.auth import hash_password

def seed_admin():
    db = SessionLocal()

    existing = db.query(User).filter(User.username == "admin").first()
    if existing:
        print("Admin already exists.")
        return

    admin = User(
        username="admin",
        password_hash=hash_password("admin123"),
        role="admin"
    )

    db.add(admin)
    db.commit()
    db.close()

    print("Admin user created: admin / admin123")


if __name__ == "__main__":
    init_db()
    seed_admin()
