from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException as StarletteHTTPException

import models
from database import Base, engine, get_db
from schemas import PostCreate, PostResponse, UserCreate, UserResponse


SESSION_COOKIE = "voting_session"
CSRF_COOKIE = "voting_csrf"
SESSION_DURATION_SECONDS = 14 * 24 * 60 * 60
PASSWORD_HASH_ITERATIONS = 310_000

Base.metadata.create_all(bind=engine)

candidate_defaults = [
    models.Candidate(
        name="Bola Ahmed TINUBUUUUUUUU!!!!!",
        party="ALL PROGRESSIVE CONGRESS(APC)",
        description="4+4 Emi Lo Kan.",
    ),
    models.Candidate(
        name="Peter Gregory Obi",
        party="NIGERIA DEMOCRATIC CONGRESS(NDC)",
        description="From consumption to production.",
    ),
]

db = next(get_db())
try:
    existing_candidates = db.scalars(
        select(models.Candidate).order_by(models.Candidate.id)
    ).all()
    if not existing_candidates:
        db.add_all(candidate_defaults)
        db.commit()
    else:
        for candidate, default in zip(existing_candidates, candidate_defaults):
            if candidate.name in {"Candidate One", "Candidate Two"}:
                candidate.name = default.name
                candidate.party = default.party
                candidate.description = default.description
        db.commit()
finally:
    db.close()


app = FastAPI(title="Civic Vote")
app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/media", StaticFiles(directory="media"), name="media")
templates = Jinja2Templates(directory="templates")


def _utc_now():
    return models.datetime.now(models.UTC).replace(tzinfo=None)


def _hash_password(password: str) -> str:
    salt = models.secrets.token_bytes(16)
    digest = models.hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS
    )
    return (
        f"pbkdf2_sha256${PASSWORD_HASH_ITERATIONS}"
        f"${salt.hex()}${digest.hex()}"
    )


def _verify_password(password: str, stored_hash: str | None) -> bool:
    if not stored_hash:
        return False
    try:
        algorithm, iterations_text, salt_text, expected = stored_hash.split("$")
        iterations = int(iterations_text)
        if algorithm != "pbkdf2_sha256" or not 1 <= iterations <= 1_000_000:
            return False
        actual = models.hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_text), iterations
        ).hex()
    except (TypeError, ValueError):
        return False
    return models.hmac.compare_digest(actual, expected)


def _csrf_token() -> str:
    return models.secrets.token_urlsafe(32)


def _set_csrf_cookie(response, request: Request, token: str) -> None:
    response.set_cookie(
        CSRF_COOKIE,
        token,
        max_age=SESSION_DURATION_SECONDS,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="lax",
        path="/",
    )


def _set_session_cookies(response, request: Request, raw_token: str, csrf_token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        raw_token,
        max_age=SESSION_DURATION_SECONDS,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="lax",
        path="/",
    )
    _set_csrf_cookie(response, request, csrf_token)


def _get_login_session(request: Request, db: Session) -> models.LoginSession | None:
    raw_token = request.cookies.get(SESSION_COOKIE)
    if not raw_token:
        return None
    token_hash = models.hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    return db.scalar(
        select(models.LoginSession)
        .where(
            models.LoginSession.token_hash == token_hash,
            models.LoginSession.expires_at > _utc_now(),
        )
        .limit(1)
    )


def _valid_csrf(
    request: Request, submitted_token: str, login_session: models.LoginSession | None
) -> bool:
    cookie_token = request.cookies.get(CSRF_COOKIE, "")
    return bool(
        cookie_token
        and models.hmac.compare_digest(cookie_token, submitted_token)
        and (
            login_session is None
            or models.hmac.compare_digest(login_session.csrf_token, submitted_token)
        )
    )


def _create_login_session(
    db: Session, user: models.VotingUser
) -> tuple[str, str]:
    raw_token = models.secrets.token_urlsafe(32)
    csrf_token = _csrf_token()
    db.add(
        models.LoginSession(
            user_id=user.id,
            token_hash=models.hashlib.sha256(raw_token.encode("utf-8")).hexdigest(),
            csrf_token=csrf_token,
            expires_at=_utc_now() + models.timedelta(seconds=SESSION_DURATION_SECONDS),
        )
    )
    db.commit()
    return raw_token, csrf_token


def _redirect(location: str):
    return JSONResponse(
        content=None,
        status_code=status.HTTP_303_SEE_OTHER,
        headers={"Location": location},
    )


def _account_page(
    request: Request,
    page: str,
    *,
    message: str | None = None,
    username: str = "",
    email: str = "",
    status_code: int = 200,
):
    csrf_token = request.cookies.get(CSRF_COOKIE) or _csrf_token()
    response = templates.TemplateResponse(
        request,
        "account.html",
        {
            "page": page,
            "title": "Create account" if page == "register" else "Sign in",
            "csrf_token": csrf_token,
            "message": message,
            "username": username,
            "email": email,
        },
        status_code=status_code,
    )
    if request.cookies.get(CSRF_COOKIE) != csrf_token:
        _set_csrf_cookie(response, request, csrf_token)
    return response


def _candidate_results(db: Session) -> tuple[list[dict], int]:
    rows = db.execute(
        select(models.Candidate, models.Vote.id)
        .outerjoin(models.Vote, models.Vote.candidate_id == models.Candidate.id)
        .order_by(models.Candidate.id)
    ).all()
    candidates = {}
    vote_counts = {}
    for candidate, vote_id in rows:
        candidates[candidate.id] = candidate
        vote_counts[candidate.id] = vote_counts.get(candidate.id, 0) + (
            1 if vote_id is not None else 0
        )
    total_votes = sum(vote_counts.values())
    results = [
        {
            "candidate": candidates[candidate_id],
            "votes": vote_counts[candidate_id],
            "percentage": round(vote_counts[candidate_id] * 100 / total_votes)
            if total_votes
            else 0,
        }
        for candidate_id in candidates
    ]
    return results, total_votes


@app.get("/", include_in_schema=False)
def home(request: Request, db: Annotated[Session, Depends(get_db)]):
    login_session = _get_login_session(request, db)
    results, total_votes = _candidate_results(db)
    has_voted = (
        login_session is not None
        and db.scalar(
            select(models.Vote.id)
            .where(models.Vote.user_id == login_session.user_id)
            .limit(1)
        )
        is not None
    )
    csrf_token = (
        login_session.csrf_token
        if login_session
        else request.cookies.get(CSRF_COOKIE) or _csrf_token()
    )
    response = templates.TemplateResponse(
        request,
        "home.html",
        {
            "title": "Cast your vote",
            "candidates": results,
            "total_votes": total_votes,
            "current_user": login_session.user if login_session else None,
            "has_voted": has_voted,
            "csrf_token": csrf_token,
            "notice": request.query_params.get("notice"),
        },
    )
    if request.cookies.get(CSRF_COOKIE) != csrf_token:
        _set_csrf_cookie(response, request, csrf_token)
    return response


@app.get("/register", include_in_schema=False)
def register_page(request: Request):
    return _account_page(request, "register")


@app.post("/register", include_in_schema=False)
async def register(request: Request, db: Annotated[Session, Depends(get_db)]):
    form = await request.form()
    username = str(form.get("username", ""))
    email = str(form.get("email", ""))
    password = str(form.get("password", ""))
    csrf_token = str(form.get("csrf_token", ""))
    if not _valid_csrf(request, csrf_token, None):
        return _account_page(
            request, "register", message="Your form expired. Please try again.", status_code=403
        )
    clean_username = username.strip()
    clean_email = email.strip().lower()
    if not clean_username or len(clean_username) > 50:
        return _account_page(
            request,
            "register",
            message="Enter a username of up to 50 characters.",
            email=clean_email,
            status_code=400,
        )
    if (
        len(clean_email) > 120
        or "@" not in clean_email
        or "." not in clean_email.rsplit("@", 1)[-1]
    ):
        return _account_page(
            request,
            "register",
            message="Enter a valid email address.",
            username=clean_username,
            status_code=400,
        )
    if len(password) < 8 or len(password) > 128:
        return _account_page(
            request,
            "register",
            message="Your password must be between 8 and 128 characters.",
            username=clean_username,
            email=clean_email,
            status_code=400,
        )
    existing_user = db.scalar(
        select(models.VotingUser).where(
            (models.VotingUser.username == clean_username)
            | (models.VotingUser.email == clean_email)
        )
    )
    if existing_user:
        message = (
            "That username is already taken."
            if existing_user.username == clean_username
            else "An account with that email already exists."
        )
        return _account_page(
            request,
            "register",
            message=message,
            username=clean_username,
            status_code=409,
        )

    user = models.VotingUser(
        username=clean_username,
        email=clean_email,
        password_hash=_hash_password(password),
    )
    db.add(user)
    try:
        db.commit()
    except models.IntegrityError:
        db.rollback()
        return _account_page(
            request,
            "register",
            message="That username or email is already in use.",
            username=clean_username,
            status_code=409,
        )
    db.refresh(user)
    raw_token, session_csrf = _create_login_session(db, user)
    response = _redirect("/")
    _set_session_cookies(response, request, raw_token, session_csrf)
    return response


@app.get("/login", include_in_schema=False)
def login_page(request: Request):
    return _account_page(request, "login", message=request.query_params.get("notice"))


@app.post("/login", include_in_schema=False)
async def login(request: Request, db: Annotated[Session, Depends(get_db)]):
    form = await request.form()
    username = str(form.get("username", ""))
    password = str(form.get("password", ""))
    csrf_token = str(form.get("csrf_token", ""))
    if not _valid_csrf(request, csrf_token, None):
        return _account_page(
            request, "login", message="Your form expired. Please try again.", status_code=403
        )
    user = db.scalar(
        select(models.VotingUser).where(
            models.VotingUser.username == username.strip()
        )
    )
    if not user or not _verify_password(password, user.password_hash):
        return _account_page(
            request,
            "login",
            message="The username or password is incorrect.",
            username=username.strip(),
            status_code=401,
        )
    raw_token, session_csrf = _create_login_session(db, user)
    response = _redirect("/")
    _set_session_cookies(response, request, raw_token, session_csrf)
    return response


@app.post("/logout", include_in_schema=False)
async def logout(request: Request, db: Annotated[Session, Depends(get_db)]):
    form = await request.form()
    csrf_token = str(form.get("csrf_token", ""))
    login_session = _get_login_session(request, db)
    if not _valid_csrf(request, csrf_token, login_session):
        raise HTTPException(status_code=403, detail="Your form expired. Please try again.")
    if login_session:
        db.delete(login_session)
        db.commit()
    response = _redirect("/")
    response.delete_cookie(SESSION_COOKIE, path="/", samesite="lax")
    response.delete_cookie(CSRF_COOKIE, path="/", samesite="lax")
    return response


@app.post("/vote", include_in_schema=False)
async def cast_vote(request: Request, db: Annotated[Session, Depends(get_db)]):
    form = await request.form()
    candidate_id_value = str(form.get("candidate_id", ""))
    csrf_token = str(form.get("csrf_token", ""))
    login_session = _get_login_session(request, db)
    if not login_session:
        return _redirect("/login?notice=Sign+in+before+you+vote.")
    if not _valid_csrf(request, csrf_token, login_session):
        raise HTTPException(status_code=403, detail="Your form expired. Please try again.")
    if not candidate_id_value.isdecimal():
        raise HTTPException(status_code=422, detail="Choose a valid candidate.")
    candidate_id = int(candidate_id_value)
    candidate = db.get(models.Candidate, candidate_id)
    if not candidate:
        raise HTTPException(status_code=404, detail="That candidate is not on the ballot.")
    existing_vote = db.scalar(
        select(models.Vote.id)
        .where(models.Vote.user_id == login_session.user_id)
        .limit(1)
    )
    if existing_vote:
        return _redirect("/?notice=Your+vote+has+already+been+recorded.")

    db.add(
        models.Vote(
            user_id=login_session.user_id,
            candidate_id=candidate.id,
        )
    )
    try:
        db.commit()
    except models.IntegrityError:
        db.rollback()
        existing_vote = db.scalar(
            select(models.Vote.id)
            .where(models.Vote.user_id == login_session.user_id)
            .limit(1)
        )
        if not existing_vote:
            raise
        return _redirect("/?notice=Your+vote+has+already+been+recorded.")
    return _redirect("/?notice=Your+vote+has+been+recorded.+Thank+you.")


@app.get("/results", include_in_schema=False)
def results_page(request: Request, db: Annotated[Session, Depends(get_db)]):
    results, total_votes = _candidate_results(db)
    login_session = _get_login_session(request, db)
    csrf_token = (
        login_session.csrf_token
        if login_session
        else request.cookies.get(CSRF_COOKIE) or _csrf_token()
    )
    response = templates.TemplateResponse(
        request,
        "results.html",
        {
            "title": "Election results",
            "results": results,
            "total_votes": total_votes,
            "current_user": login_session.user if login_session else None,
            "csrf_token": csrf_token,
        },
    )
    if request.cookies.get(CSRF_COOKIE) != csrf_token:
        _set_csrf_cookie(response, request, csrf_token)
    return response


@app.get("/api/candidates")
def get_candidates(db: Annotated[Session, Depends(get_db)]):
    return db.scalars(select(models.Candidate).order_by(models.Candidate.id)).all()


@app.get("/api/results")
def get_results(db: Annotated[Session, Depends(get_db)]):
    results, total_votes = _candidate_results(db)
    return {
        "total_votes": total_votes,
        "results": [
            {
                "candidate_id": item["candidate"].id,
                "candidate_name": item["candidate"].name,
                "party": item["candidate"].party,
                "votes": item["votes"],
                "percentage": item["percentage"],
            }
            for item in results
        ],
    }


@app.post(
    "/api/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_user(user: UserCreate, db: Annotated[Session, Depends(get_db)]):
    existing_user = db.scalar(
        select(models.User).where(
            (models.User.username == user.username) | (models.User.email == user.email)
        )
    )
    if existing_user:
        detail = (
            "Username Already Exists"
            if existing_user.username == user.username
            else "Email Already Registered"
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)

    new_user = models.User(
        username=user.username,
        email=user.email,
    )
    db.add(new_user)
    try:
        db.commit()
    except models.IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email is already registered",
        )
    db.refresh(new_user)
    return new_user


@app.get("/api/users/{user_id}", name="get_user_api", response_model=UserResponse)
def get_user(user_id: int, db: Annotated[Session, Depends(get_db)]):
    user = db.get(models.User, user_id)
    if user:
        return user
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"User with ID {user_id} Was Not Found",
    )


@app.get("/api/posts", response_model=list[PostResponse])
def get_posts(db: Annotated[Session, Depends(get_db)]):
    return db.scalars(select(models.Post)).all()


@app.get("/api/posts/{post_id}", response_model=PostResponse)
def get_post(post_id: int, db: Annotated[Session, Depends(get_db)]):
    post = db.get(models.Post, post_id)
    if post:
        return post
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Post {post_id} Was Not Found",
    )


@app.post(
    "/api/posts",
    response_model=PostResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_post(post: PostCreate, db: Annotated[Session, Depends(get_db)]):
    user = db.get(models.User, post.user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID - {post.user_id} not found",
        )
    new_post = models.Post(
        title=post.title,
        content=post.content,
        user_id=post.user_id,
    )
    db.add(new_post)
    db.commit()
    db.refresh(new_post)
    return new_post


@app.exception_handler(StarletteHTTPException)
def http_exception_handler(request: Request, exception: StarletteHTTPException):
    message = (
        exception.detail
        if exception.detail
        else "An error occurred while processing your request. Please try again later."
    )
    if request.url.path.startswith("/api"):
        return JSONResponse(
            status_code=exception.status_code,
            content={"detail": message},
        )
    return templates.TemplateResponse(
        request,
        "error.html",
        {
            "status_code": exception.status_code,
            "title": str(exception.status_code),
            "message": message,
        },
        status_code=exception.status_code,
    )


@app.exception_handler(RequestValidationError)
def general_http_exception_handler(request: Request, exception: RequestValidationError):
    if request.url.path.startswith("/api"):
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": exception.errors()},
        )
    return templates.TemplateResponse(
        request,
        "error.html",
        {
            "status_code": status.HTTP_422_UNPROCESSABLE_ENTITY,
            "title": str(status.HTTP_422_UNPROCESSABLE_ENTITY),
            "message": "Invalid request. Please check your input and try again.",
        },
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
    )
