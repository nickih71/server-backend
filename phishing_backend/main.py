from datetime import datetime
import time

from fastapi import FastAPI, HTTPException, Form, Depends
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError

from .database import log_interaction, get_all_interactions, SessionLocal
from .models import Interaction, User
from .utils import parse_token
from .auth import hash_password, verify_password
from .email_utils import send_email
from .jwt_utils import create_access_token, SECRET_KEY, ALGORITHM

from fastapi import FastAPI
from .database import Base, engine

app = FastAPI()


@app.get("/init-db")
def init_db():
    Base.metadata.create_all(bind=engine)
    return {"status": "database initialized"}

# -----------------------------
# CORS
# -----------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "https://security-awareness-suite-itec490.netlify.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory="phishing_backend/templates")

# -----------------------------
# FRONTEND (NETLIFY) URLS
# -----------------------------
NETLIFY_BASE = "https://security-awareness-suite-itec490.netlify.app"

TRAINING_URL = f"{NETLIFY_BASE}/clicked.html"
CONGRATS_URL = f"{NETLIFY_BASE}/reported.html"

# -----------------------------
# BACKEND BASE URL (SET AFTER DEPLOY)
# -----------------------------
BACKEND_BASE = "https://YOUR-BACKEND-URL.onrender.com"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# -----------------------------
# AUTH HELPERS
# -----------------------------
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


# -----------------------------
# HEALTH CHECK
# -----------------------------
@app.get("/health")
def health_check():
    return {"status": "ok"}


# -----------------------------
# SEND TEST EMAIL
# -----------------------------
@app.get("/send-test")
def send_test():
    send_email(
        to_email="nicole.hogan@ku.edu",
        base_url=BACKEND_BASE,
        token="test123",
    )
    return {"status": "sent"}


# -----------------------------
# CLICKED PHISHING LINK
# -----------------------------
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


# -----------------------------
# REPORTED PHISHING EMAIL
# -----------------------------
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


# -----------------------------
# LOGIN
# -----------------------------
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


# -----------------------------
# VIEW LOGS (ADMIN ONLY)
# -----------------------------
@app.get("/logs")
def view_logs(user=Depends(require_admin)):
    return get_all_interactions()


# -----------------------------
# CREATE USER (ADMIN ONLY)
# -----------------------------
@app.post("/create-user")
def create_user(
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("user"),
 #   user=Depends(require_admin),
):
    db = SessionLocal()
    existing = db.query(User).filter(User.username == username).first()

    if existing:
        db.close()
        raise HTTPException(status_code=400, detail="Username already exists")

    new_user = User(
        username=username,
        password_hash=hash_password(password),
        role=role,
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    db.close()

    return {"status": "user created", "username": username, "role": role}


# -----------------------------
# LAUNCH PHISHING (ADMIN ONLY)
# -----------------------------
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
            time.sleep(1)  # Mailtrap free tier = 1 email/sec

    db.close()
    return {"status": "phishing emails launched"}


# -----------------------------
# RESET PASSWORD (ADMIN ONLY)
# -----------------------------
@app.post("/reset-password")
def reset_password(
    username: str = Form(...),
    new_password: str = Form(...),
    user=Depends(require_admin),
):
    db = SessionLocal()
    target = db.query(User).filter(User.username == username).first()

    if not target:
        db.close()
        raise HTTPException(status_code=404, detail="User not found")

    target.password_hash = hash_password(new_password)
    db.commit()
    db.close()

    return {"status": "password reset", "username": username}
