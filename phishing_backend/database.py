from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from .models import Base, Interaction

DATABASE_URL = "sqlite:///./phishing.db"

engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
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
