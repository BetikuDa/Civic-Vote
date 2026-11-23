import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException as StarletteHTTPException

import models
from database import Base, engine, get_db
from schemas import PostCreate, PostResponse, UserCreate, UserResponse


Base.metadata.create_all(bind=engine)
if "password_hash" not in {
    column["name"] for column in inspect(engine).get_columns("users")
}:
    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE users ADD COLUMN password_hash VARCHAR(256)"))


app = FastAPI(title="Civic Vote")
app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/media", StaticFiles(directory="media"), name="media")
templates = Jinja2Templates(directory="templates")

SESSION_COOKIE = "civic_session"
PASSWORD_ITERATIONS = 310_000
SESSION_LIFETIME = timedelta(days=7)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt.hex()}${password_hash.hex()}"


def verify_password(password: str, stored_hash: str | None) -> bool:
    if not stored_hash:
        return False
    try:
        algorithm, iterations, salt, expected_hash = stored_hash.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        actual_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iterations)
        ).hex()
        return hmac.compare_digest(actual_hash, expected_hash)
    except (ValueError, TypeError):
        return False


def get_authentication(request: Request, db: Session):
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None, None
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    auth_session = db.execute(
        select(models.LoginSession).where(models.LoginSession.token_hash == token_hash)
    ).scalars().first()
    if not auth_session:
        return None, None
    if auth_session.expires_at < datetime.now(UTC).replace(tzinfo=None):
        return None, None
    user = db.get(models.User, auth_session.user_id)
    if not user:
        return None, None
    return user, auth_session


def create_authentication(user: models.User, db: Session, request: Request):
    token = secrets.token_urlsafe(32)
    auth_session = models.LoginSession(
        user_id=user.id,
        token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
        csrf_token=secrets.token_urlsafe(32),
        expires_at=datetime.now(UTC).replace(tzinfo=None) + SESSION_LIFETIME,
    )
    db.add(auth_session)
    db.commit()
    response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=int(SESSION_LIFETIME.total_seconds()),
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="lax",
        path="/",
    )
    return response


def verify_csrf(request: Request, auth_session: models.LoginSession, token: str):
    if not hmac.compare_digest(auth_session.csrf_token, token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Your form expired. Please try again.")


def election_results(db: Session):
    candidates = db.execute(
        select(models.Candidate).order_by(models.Candidate.position)
    ).scalars().all()
    counts = {
        candidate_id: vote_count
        for candidate_id, vote_count in db.execute(
            select(models.Vote.candidate_id, func.count(models.Vote.id))
            .group_by(models.Vote.candidate_id)
        ).all()
    }
    total_votes = sum(counts.values())
    return [
        {
            "candidate": candidate,
            "votes": counts.get(candidate.id, 0),
            "percentage": round(counts.get(candidate.id, 0) * 100 / total_votes)
            if total_votes
            else 0,
        }
        for candidate in candidates
    ], total_votes


def render_auth(request: Request, mode: str, error: str | None = None, status_code: int = 200):
    return templates.TemplateResponse(
        request,
        "auth.html",
        {"title": "Create your account" if mode == "register" else "Sign in", "mode": mode, "error": error},
        status_code=status_code,
    )


@app.get("/", include_in_schema=False)
def home(request: Request, db: Annotated[Session, Depends(get_db)]):
    if not db.execute(select(models.Candidate.id)).first():
        return templates.TemplateResponse(request, "setup.html", {"title": "Set up the election"})
    user, auth_session = get_authentication(request, db)
    results, total_votes = election_results(db)
    has_voted = bool(
        user
        and db.execute(
            select(models.Vote.id).where(models.Vote.user_id == user.id)
        ).first()
    )
    return templates.TemplateResponse(
        request,
        "home.html",
        {
            "title": "Your vote. Your voice.",
            "user": user,
            "csrf_token": auth_session.csrf_token if auth_session else "",
            "results": results,
            "total_votes": total_votes,
            "has_voted": has_voted,
        },
    )


@app.post("/setup", include_in_schema=False)
async def setup_election(request: Request, db: Annotated[Session, Depends(get_db)]):
    form = await request.form()
    names = [str(form.get("candidate_one", "")).strip(), str(form.get("candidate_two", "")).strip()]
    if any(not name or len(name) > 80 for name in names) or names[0].casefold() == names[1].casefold():
        return templates.TemplateResponse(
            request,
            "setup.html",
            {"title": "Set up the election", "error": "Enter two different candidate names (up to 80 characters each)."},
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    if db.execute(select(models.Candidate.id)).first():
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    db.add_all(
        [
            models.Candidate(name=names[0], position=1),
            models.Candidate(name=names[1], position=2),
        ]
    )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        if db.execute(select(models.Candidate.id)).first():
            return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="The election could not be created.")
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/register", include_in_schema=False)
def register_page(request: Request):
    return render_auth(request, "register")


@app.post("/register", include_in_schema=False)
async def register(request: Request, db: Annotated[Session, Depends(get_db)]):
    form = await request.form()
    username = str(form.get("username", "")).strip()
    email = str(form.get("email", "")).strip().lower()
    password = str(form.get("password", ""))
    if not username or len(username) > 50:
        return render_auth(request, "register", "Choose a username up to 50 characters.", 400)
    if len(email) > 120 or "@" not in email:
        return render_auth(request, "register", "Enter a valid email address.", 400)
    if len(password) < 8 or len(password) > 128:
        return render_auth(request, "register", "Your password must be between 8 and 128 characters.", 400)
    if db.execute(
        select(models.User.id).where(
            (models.User.username == username) | (models.User.email == email)
        )
    ).first():
        return render_auth(request, "register", "That username or email is already registered.", 400)
    user = models.User(username=username, email=email, password_hash=hash_password(password))
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        if db.execute(
            select(models.User.id).where(
                (models.User.username == username) | (models.User.email == email)
            )
        ).first():
            return render_auth(request, "register", "That username or email is already registered.", 400)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Your account could not be created.")
    db.refresh(user)
    return create_authentication(user, db, request)


@app.get("/login", include_in_schema=False)
def login_page(request: Request):
    return render_auth(request, "login")


@app.post("/login", include_in_schema=False)
async def login(request: Request, db: Annotated[Session, Depends(get_db)]):
    form = await request.form()
    identifier = str(form.get("identifier", "")).strip()
    password = str(form.get("password", ""))
    user = db.execute(
        select(models.User).where(
            (models.User.username == identifier) | (models.User.email == identifier.lower())
        )
    ).scalars().first()
    if not user or not verify_password(password, user.password_hash):
        return render_auth(request, "login", "The username/email or password is incorrect.", 401)
    return create_authentication(user, db, request)


@app.post("/logout", include_in_schema=False)
async def logout(request: Request, db: Annotated[Session, Depends(get_db)]):
    user, auth_session = get_authentication(request, db)
    if not user or not auth_session:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    form = await request.form()
    verify_csrf(request, auth_session, str(form.get("csrf_token", "")))
    db.delete(auth_session)
    db.commit()
    response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(SESSION_COOKIE, path="/", samesite="lax")
    return response


@app.post("/vote", include_in_schema=False)
async def cast_vote(request: Request, db: Annotated[Session, Depends(get_db)]):
    user, auth_session = get_authentication(request, db)
    if not user or not auth_session:
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    form = await request.form()
    verify_csrf(request, auth_session, str(form.get("csrf_token", "")))
    candidate_id = form.get("candidate_id")
    if not candidate_id or not str(candidate_id).isdigit():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Choose one of the candidates.")
    candidate = db.get(models.Candidate, int(candidate_id))
    if not candidate:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Choose one of the candidates.")
    db.add(models.Vote(user_id=user.id, candidate_id=candidate.id))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        if db.execute(
            select(models.Vote.id).where(models.Vote.user_id == user.id)
        ).first():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Your account has already voted.")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Your vote could not be recorded.")
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/results", include_in_schema=False)
def results_page(request: Request, db: Annotated[Session, Depends(get_db)]):
    results, total_votes = election_results(db)
    return templates.TemplateResponse(
        request,
        "results.html",
        {"title": "Election results", "results": results, "total_votes": total_votes},
    )


@app.post("/api/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user_api(user: UserCreate, db: Annotated[Session, Depends(get_db)]):
    if db.execute(
        select(models.User.id).where(
            (models.User.username == user.username) | (models.User.email == str(user.email).lower())
        )
    ).first():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username or email is already registered")
    new_user = models.User(
        username=user.username,
        email=str(user.email).lower(),
        password_hash=hash_password(user.password),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.get("/api/users/{user_id}", response_model=UserResponse)
def get_user_api(user_id: int, db: Annotated[Session, Depends(get_db)]):
    user = db.get(models.User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User with ID {user_id} was not found")
    return user


@app.get("/api/posts", response_model=list[PostResponse])
def get_posts_api(db: Annotated[Session, Depends(get_db)]):
    return db.execute(select(models.Post)).scalars().all()


@app.get("/api/posts/{post_id}", response_model=PostResponse)
def get_post_api(post_id: int, db: Annotated[Session, Depends(get_db)]):
    post = db.get(models.Post, post_id)
    if not post:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Post {post_id} was not found")
    return post


@app.post("/api/posts", response_model=PostResponse, status_code=status.HTTP_201_CREATED)
def create_post_api(post: PostCreate, db: Annotated[Session, Depends(get_db)]):
    if not db.get(models.User, post.user_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User with ID {post.user_id} not found")
    new_post = models.Post(title=post.title, content=post.content, user_id=post.user_id)
    db.add(new_post)
    db.commit()
    db.refresh(new_post)
    return new_post


@app.exception_handler(StarletteHTTPException)
def http_exception_handler(request: Request, exception: StarletteHTTPException):
    if request.url.path.startswith("/api"):
        return JSONResponse(status_code=exception.status_code, content={"detail": exception.detail})
    return templates.TemplateResponse(
        request,
        "error.html",
        {"status_code": exception.status_code, "title": "Something went wrong", "message": exception.detail},
        status_code=exception.status_code,
    )


@app.exception_handler(RequestValidationError)
def validation_exception_handler(request: Request, exception: RequestValidationError):
    if request.url.path.startswith("/api"):
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"detail": exception.errors()})
    return templates.TemplateResponse(
        request,
        "error.html",
        {"status_code": status.HTTP_422_UNPROCESSABLE_ENTITY, "title": "Invalid request", "message": "Please check your input and try again."},
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
    )
