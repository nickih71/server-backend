import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Base, Interaction

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./phishing.db")

# PostgreSQL URLs from Render start with "postgres://"
# but SQLAlchemy requires "postgresql://"
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)

def log_interaction(interaction: Interaction):
    db = SessionLocal()
    db.add(interaction)
    db.commit()
    db.close()

def get_all_interactions():
    db = SessionLocal()
    interactions = db.query(Interaction).all()
    db.close()
    return interactions
