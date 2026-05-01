from datetime import datetime
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Form, Depends
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError

from .database import Base, engine, SessionLocal, log_interaction, get_all_interactions
from .models import Interaction, User
from .utils import parse_token
from .auth import hash_password, verify_password
from .email_utils import send_email
from .jwt_utils import create_access_token, SECRET_KEY, ALGORITHM


# ---------------------------------------------------------
# Lifespan: Runs BEFORE the app starts serving requests
# ---------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables
    Base.metadata.create_all(bind=engine)

    # Seed admin user
    db = SessionLocal()
    try:
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
        scts_user = db.query(User).filter(User.username == "safework490.demo@gmail.com").first()
        if not scts_user:
            scts_user = User(
                username="safework490.demo@gmail.com",
                password_hash=hash_password("Scts_spr26"),
                role="user"
            )
            db.add(scts_user)
            db.commit()
            print("SCTS user created.")
        else:
            print("SCTS user already exists.")
    finally:
        db.close()

    yield  # App starts here


# ---------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------
app = FastAPI(lifespan=lifespan)


# ---------------------------------------------------------
# CORS
# ---------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://security-awareness-suite-itec490.netlify.app",
        "http://127.0.0.1:5500",
        "http://localhost:5500",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory="phishing_backend/templates")


# ---------------------------------------------------------
# FRONTEND URLS
# ---------------------------------------------------------
NETLIFY_BASE = "https://security-awareness-suite-itec490.netlify.app"
TRAINING_URL = f"{NETLIFY_BASE}/clicked.html"
CONGRATS_URL = f"{NETLIFY_BASE}/reported.html"

# Replace this with your actual Render backend URL
BACKEND_BASE = "https://server-backend-dz7b.onrender.com"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# ---------------------------------------------------------
# AUTH HELPERS
# ---------------------------------------------------------
def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def require_admin(user=Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# ---------------------------------------------------------
# ROUTES
# ---------------------------------------------------------

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.get("/clicked/{token}")
def clicked_link(token: str):
    user_id = parse_token(token)
    log_interaction(
        Interaction(
            user_id=user_id,
            token=token,
            action="clicked",
            timestamp=datetime.utcnow(),
        )
    )
    return RedirectResponse(url=TRAINING_URL)

@app.get("/report/{token}")
def report_phishing(token: str):
    user_id = parse_token(token)
    log_interaction(
        Interaction(
            user_id=user_id,
            token=token,
            action="reported",
            timestamp=datetime.utcnow(),
        )
    )
    return RedirectResponse(url=CONGRATS_URL)

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    db = SessionLocal()
    user = db.query(User).filter(User.username == username).first()

    if not user or not verify_password(password, user.password_hash):
        db.close()
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_access_token({"sub": user.username, "role": user.role})
    db.close()

    return {"access_token": token, "token_type": "bearer"}

@app.post("/launch-phishing")
def launch_phishing(user=Depends(require_admin)):
    db = SessionLocal()
    users = db.query(User).all()

    for u in users:
        if u.role == "user":
            send_email(
                to_email=u.username,
                base_url=BACKEND_BASE,
                token=f"{u.username}-{int(datetime.utcnow().timestamp())}",
            )
            time.sleep(10)

    db.close()
    return {"status": "phishing emails launched"}


