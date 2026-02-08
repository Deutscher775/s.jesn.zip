from fastapi import File, UploadFile, Form, Depends, Request, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse, FileResponse
from typing import Optional, Dict
import fastapi
import uvicorn
import pathlib
import json
import os
import sys
import string
import secrets  # Cryptographically secure random
import random  # For random word selection
from starlette.middleware.base import BaseHTTPMiddleware
import threading
import time
import mimetypes
import subprocess
import re
import queue
import bcrypt
from surrealdb import Surreal
import config
import shutil
from urllib.parse import urlparse
from collections import defaultdict
from file_manager import get_file_manager, set_upload_directory
from fastapi.middleware.cors import CORSMiddleware
import logging
import hmac
import contextlib

# Note: fcntl is imported inside file_lock() function for Unix file locking

# Check for --install-deps flag
if "--install-deps" in sys.argv:
    if os.name != "posix":
        print("Automatic dependency installation is only supported on Linux.")
        sys.exit(1)
    
    print("Installing required dependencies...")
    try:
        subprocess.run(["sudo", "apt-get", "update"], check=True)
        subprocess.run(["sudo", "apt-get", "install", "-y", "ffmpeg", "poppler-utils"], check=True)
        print("Dependencies installed successfully!")
        sys.exit(0)
    except subprocess.CalledProcessError as e:
        print(f"Failed to install dependencies: {e}")
        sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO if config.IS_PRODUCTION else logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Security helper functions
def generate_secure_token(length: int = 64) -> str:
    """Generate a cryptographically secure random token."""
    return secrets.token_urlsafe(length)

def validate_password_strength(password: str) -> tuple[bool, str]:
    """Validate password meets security requirements."""
    if len(password) < config.MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {config.MIN_PASSWORD_LENGTH} characters long"
    
    if config.REQUIRE_PASSWORD_UPPERCASE and not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    
    if config.REQUIRE_PASSWORD_NUMBER and not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    
    if config.REQUIRE_PASSWORD_SPECIAL_CHAR and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        return False, "Password must contain at least one special character"
    
    return True, ""

def validate_url(url: str) -> bool:
    """Validate URL format and scheme."""
    try:
        result = urlparse(url)
        return all([result.scheme in ('http', 'https'), result.netloc])
    except:
        return False

def validate_file_extension(filename: str) -> tuple[bool, str]:
    """Validate file extension is allowed and not blocked."""
    ext = os.path.splitext(filename.lower())[1]
    
    if ext in config.BLOCKED_EXTENSIONS:
        return False, f"File extension '{ext}' is not allowed for security reasons"
    
    if config.ALLOWED_EXTENSIONS and ext not in config.ALLOWED_EXTENSIONS:
        return False, f"File extension '{ext}' is not in the allowed list"
    
    return True, ""

def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal."""
    # Remove path separators and null bytes
    filename = filename.replace('/', '').replace('\\', '').replace('\x00', '')
    # Remove leading dots to prevent hidden files
    filename = filename.lstrip('.')
    # Remove any remaining dangerous characters
    filename = re.sub(r'[<>:"|?*]', '', filename)
    return filename

def safe_error_response(status_code: int, error_msg: str, details: str = None) -> JSONResponse:
    """Return safe error response, hiding details in production."""
    content = {"error": error_msg}
    if not config.IS_PRODUCTION and details:
        content["details"] = details
    return JSONResponse(status_code=status_code, content=content)

random_words = list(set([
    "apple", "grape", "peach", "plum", "berry", "melon", "lemon", "mango", "olive", "pearl",
    "stone", "flame", "blaze", "spark", "ember", "glow", "shine", "chickenjokey", "gleam", "flash", "flare",
    "storm", "cloud", "rainy", "sunny", "windy", "breez", "lol", "frost", "snowy", "chill", "blizz",
    "mount", "ridge", "69", "valle", "plain", "field", "ligma", "meado", "grove", "woods", "forest", "jungle",
    "river", "creek", "brook", "stream", "ocean", "beach", "shore", "coast", "islan", "coral",
    "eagle", "hawk", "jesn", "L347", "falco", "robin", "sparr", "finch", "swall", "heron", "crane", "stork",
    "tiger", "lion", "leopa", "cheet", "puma", "jagua", "lynx", "couga", "420", "panth", "ocelo",
    "horse", "zebra", "donke", "mule", "camel", "sheep", "goat", "ram", "nahundgut",
    "whale", "dolph", "shark", "ray", "eel", "octop", "squid", "crab", "lobster", "shrimp",
    "banana", "kiwi", "papaya", "guava", "fig", "date", "quince", "apricot",
    "volcano", "geyser", "canyon", "cliff", "dune", "glacier", "hill", "mesa", "plateau", "valley",
    "falcon", "owl", "parrot", "pigeon", "crow", "raven",
    "bear", "wolf", "fox", "otter", "weasel", "badger", "ferret",
    "bison", "yak", "gazelle", "ibex", "moose", "caribou", "elk",
    "seal", "walrus", "narwhal", "l347", "orca", "beluga", "penguin"
    "school", "college", "university", "academy", "institute", "center", "lab", "library", "museum", "gallery",
    "garden", "park", "zoo", "theater", "cinema", "studio", "station",
    "circle", "square", "plaza", "court", "ao", "lane", "drive", "way", "path", "trail", "track",
    "pizza", "pasta", "burger", "taco", "burrito", "sushi", "ramen", "pho", "curry", "kebab",
    "coffee", "tea", "juice", "soda", "beer", "wine", "whisky", "vodka", "rum", "gin",
    "cake", "cookie", "pie", "pudding", "candy", "chocolate", "caramel", "fudge", "jelly"
]))

# Dictionary to track conversion progress
conversion_progress = {}

# Allowed output formats for conversion (security whitelist)
ALLOWED_CONVERSION_FORMATS = {
    # Video formats
    'mp4', 'webm', 'mkv', 'avi', 'mov', 'flv', 'wmv', 'mpeg', 'mpg',
    # Audio formats
    'mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a', 'wma',
    # Image formats
    'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'tiff',
    # Document formats
    'pdf',
}

app = fastapi.FastAPI()

# Database connection pool
class DatabasePool:
    """Database connection pool for SurrealDB with health checks and reconnection"""
    def __init__(self, url: str, namespace: str, database: str, user: str, password: str, pool_size: int = 10):
        self.url = url
        self.namespace = namespace
        self.database = database
        self.user = user
        self.password = password
        self.pool_size = pool_size
        self._pool = queue.Queue(maxsize=pool_size)
        self._lock = threading.Lock()
        self._connection_timestamps = {}  # Track when connections were created
        self._max_connection_age = 300  # Max 5 minutes before refresh
        
    async def _create_connection(self):
        """Create a new database connection"""
        db = Surreal(self.url)
        await db.connect()
        await db.signin({"user": self.user, "pass": self.password})
        await db.use(self.namespace, self.database)
        # Track connection creation time
        self._connection_timestamps[id(db)] = time.time()
        return db
    
    async def _is_connection_healthy(self, db) -> bool:
        """Check if a connection is still valid"""
        try:
            # Check connection age
            conn_id = id(db)
            created_at = self._connection_timestamps.get(conn_id, 0)
            if time.time() - created_at > self._max_connection_age:
                logger.debug(f"Connection {conn_id} is too old, will create new one")
                return False
            
            # Try a simple query to verify connection
            await db.query("SELECT 1")
            return True
        except Exception as e:
            logger.debug(f"Connection health check failed: {e}")
            return False
    
    async def _close_connection(self, db):
        """Safely close a database connection"""
        try:
            conn_id = id(db)
            if conn_id in self._connection_timestamps:
                del self._connection_timestamps[conn_id]
            await db.close()
        except Exception as e:
            logger.debug(f"Error closing connection: {e}")
    
    async def get_connection(self):
        """Get a healthy connection from the pool or create a new one"""
        # Try to get a healthy connection from pool
        attempts = 0
        max_attempts = self.pool_size
        
        while attempts < max_attempts:
            try:
                db = self._pool.get_nowait()
                if await self._is_connection_healthy(db):
                    return db
                else:
                    # Connection is stale, close it and try again
                    await self._close_connection(db)
                    attempts += 1
            except queue.Empty:
                # Pool is empty, create new connection
                break
        
        # Create new connection
        try:
            return await self._create_connection()
        except Exception as e:
            logger.error(f"Failed to create database connection: {e}")
            raise
    
    async def release_connection(self, db):
        """Return a connection to the pool if healthy, otherwise discard"""
        try:
            # Only return to pool if it's not full
            self._pool.put_nowait(db)
        except queue.Full:
            # Pool is full, close this connection
            await self._close_connection(db)

# Initialize database pool
db_pool = None

async def get_db():
    """Get a database connection from the pool"""
    global db_pool
    if db_pool is None:
        db_pool = DatabasePool(
            url=config.DATABASE_URL,
            namespace=config.NAMESPACE_NAME,
            database=config.DATABASE_NAME,
            user=config.DATABASE_USER,
            password=config.DATABASE_PASSWORD,
            pool_size=10
        )
    return await db_pool.get_connection()

async def release_db(db):
    """Release a database connection back to the pool"""
    if db_pool:
        await db_pool.release_connection(db)

# Auth-Dependency (vor allen Endpunkten!)

# Track failed login attempts for account lockout
failed_login_attempts: Dict[str, list] = defaultdict(list)
ACCOUNT_LOCKOUT_THRESHOLD = config.ACCOUNT_LOCKOUT_THRESHOLD if hasattr(config, 'ACCOUNT_LOCKOUT_THRESHOLD') else 5
ACCOUNT_LOCKOUT_DURATION = config.ACCOUNT_LOCKOUT_DURATION if hasattr(config, 'ACCOUNT_LOCKOUT_DURATION') else 900


def timing_safe_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))


async def migrate_user_schema(db, user: dict) -> dict:
    """
    Migrate user record to current schema if fields are missing.
    Preserves all existing data, especially files.
    Returns the updated user dict.
    """
    needs_update = False
    username = user.get("username")
    
    # Define expected schema with default values
    schema_defaults = {
        "session_keys": [],
        "session_data": {},
        "files": [],  # Preserve existing files, default to empty list
        "oauth_tokens": {},
        "created_at": time.time(),
        "last_login": None,
    }
    
    # Check each field and add if missing
    for field, default_value in schema_defaults.items():
        if field not in user or user.get(field) is None:
            # Special handling for 'files' - never overwrite with empty if it exists
            if field == "files" and "files" in user:
                continue
            user[field] = default_value
            needs_update = True
            logger.info(f"Migrating user '{username}': adding missing field '{field}'")
    
    # Ensure correct types for existing fields
    if not isinstance(user.get("session_keys"), list):
        user["session_keys"] = []
        needs_update = True
    
    if not isinstance(user.get("session_data"), dict):
        user["session_data"] = {}
        needs_update = True
    
    if not isinstance(user.get("files"), list):
        # If files is not a list but exists, try to preserve it
        existing_files = user.get("files")
        if existing_files is not None:
            logger.warning(f"User '{username}' has invalid files type: {type(existing_files)}, preserving as-is")
        else:
            user["files"] = []
            needs_update = True
    
    if not isinstance(user.get("oauth_tokens"), dict):
        user["oauth_tokens"] = {}
        needs_update = True
    
    # Update database if changes were made
    if needs_update and username:
        try:
            await db.query(
                "UPDATE users SET session_keys = $session_keys, session_data = $session_data, "
                "files = $files, oauth_tokens = $oauth_tokens, created_at = $created_at, "
                "last_login = $last_login WHERE username = $username",
                {
                    "session_keys": user["session_keys"],
                    "session_data": user["session_data"],
                    "files": user["files"],
                    "oauth_tokens": user["oauth_tokens"],
                    "created_at": user.get("created_at", time.time()),
                    "last_login": user.get("last_login"),
                    "username": username
                }
            )
            logger.info(f"Successfully migrated schema for user '{username}'")
        except Exception as e:
            logger.error(f"Failed to migrate schema for user '{username}': {e}")
    
    return user


async def get_auth_status(request: Request, check_password: str = None):
    db = None
    try:
        if check_password:
            db = await get_db()
            result = await db.query("SELECT * FROM users WHERE username = $username", {"username": request.path_params.get("username")})
            users = result[0].get("result", [])
            if not users:
                return False
            user = users[0]
            stored_hash = user.get("password", "")
            return bcrypt.checkpw(check_password.encode(), stored_hash.encode())
        
        session_key = request.headers.get("Authorization")
        if not session_key:
            return None
        
        db = await get_db()
        
        # Find user with this session key
        result = await db.query("SELECT * FROM users WHERE $session_key INSIDE session_keys", {"session_key": session_key})
        users = result[0].get("result", [])
        if not users:
            return False
        
        user = users[0]
        
        # Check session expiration if session has timestamp
        session_data = user.get("session_data", {})
        if isinstance(session_data, dict) and session_key in session_data:
            created_at = session_data[session_key].get("created_at", 0)
            expiry_seconds = config.SESSION_EXPIRY_HOURS * 3600
            if time.time() - created_at > expiry_seconds:
                # Session expired, remove it
                session_keys = user.get("session_keys", [])
                if session_key in session_keys:
                    session_keys.remove(session_key)
                    del session_data[session_key]
                    await db.query(
                        "UPDATE users SET session_keys = $keys, session_data = $data WHERE username = $username",
                        {"keys": session_keys, "data": session_data, "username": user["username"]}
                    )
                return False
        
        return True
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Auth error: {e}")
        return None
    finally:
        if db:
            await release_db(db)

# Rate limiting storage
rate_limit_storage: Dict[str, list] = defaultdict(list)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware to prevent brute force and DoS attacks."""
    
    async def dispatch(self, request, call_next):
        # Get client IP (consider X-Forwarded-For for reverse proxy setups)
        client_ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown")
        if "," in client_ip:
            client_ip = client_ip.split(",")[0].strip()
        
        current_time = time.time()
        window_start = current_time - config.RATE_LIMIT_WINDOW_SECONDS
        
        # Clean old requests
        rate_limit_storage[client_ip] = [
            ts for ts in rate_limit_storage[client_ip] if ts > window_start
        ]
        
        # Check rate limit
        if len(rate_limit_storage[client_ip]) >= config.RATE_LIMIT_REQUESTS:
            return JSONResponse(
                status_code=429,
                content={"error": "Too many requests. Please try again later."},
                headers={"Retry-After": str(config.RATE_LIMIT_WINDOW_SECONDS)}
            )
        
        # Record this request
        rate_limit_storage[client_ip].append(current_time)
        
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""
    
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Content Security Policy
        if config.IS_PRODUCTION:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self'; "
                "frame-ancestors 'none';"
            )
        
        # HSTS header for HTTPS
        if config.IS_PRODUCTION:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        return response


class LimitRequestSizeMiddleware(BaseHTTPMiddleware):
    """Limit request size to prevent DoS attacks."""
    
    async def dispatch(self, request, call_next):
        max_request_size = config.MAX_REQUEST_SIZE_MB * 1024 * 1024
        if request.headers.get("content-length") and int(request.headers["content-length"]) > max_request_size:
            return JSONResponse(
                status_code=413, 
                content={"error": f"Payload Too Large. Maximum file size is {config.MAX_REQUEST_SIZE_MB} MB."}
            )
        return await call_next(request)


# Add middleware in correct order (first added = outermost)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(LimitRequestSizeMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS if config.IS_PRODUCTION else ["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "PUT", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Origin", "Accept"],
)


@app.get("/")
def read_root():
    return fastapi.responses.RedirectResponse(url="/create", status_code=302)


@app.get("/create")
def render_create_webinterface():
    with open("./webinterface/create.html", "r", encoding="utf-8") as f:
        return fastapi.responses.HTMLResponse(content=f.read())


@app.get("/privacy.html")
def render_privacy_html():
    with open("./webinterface/privacy.html", "r", encoding="utf-8") as f:
        return fastapi.responses.HTMLResponse(content=f.read())


@app.get("/privacy")
def render_privacy_webinterface():
    with open("./webinterface/privacy.html", "r", encoding="utf-8") as f:
        return fastapi.responses.HTMLResponse(content=f.read())


@app.get("/imprint")
def render_imprint_webinterface():
    with open("./webinterface/imprint.html", "r", encoding="utf-8") as f:
        return fastapi.responses.HTMLResponse(content=f.read())

@app.get("/favicon.ico")
def render_favicon():
    return fastapi.responses.FileResponse(f"{pathlib.Path(__file__).parent.resolve()}/webinterface/s.jesn.zip icon.ico")


@app.get("/{share_path}")
def read_share(share_path: str):
    try:
        with open("urls.txt", "r") as shares_file:
            shares = shares_file.readlines()
        for share in shares:
            share = share.strip()
            if share_path in share:
                share = share.split(";")
                return fastapi.responses.RedirectResponse(url=share[1], status_code=302)
        return fastapi.responses.JSONResponse(status_code=404, content={"error": "Share not found"})
    except FileNotFoundError:
        logger.error("urls.txt not found")
        return fastapi.responses.JSONResponse(status_code=500, content={"error": "Service configuration error"})
    except Exception as e:
        logger.error(f"Error reading share: {e}")
        return fastapi.responses.JSONResponse(status_code=500, content={"error": "Internal server error"})


@contextlib.contextmanager
def file_lock(file_path, mode='r'):
    """Context manager for file locking (works on Unix/Linux, no-op on Windows)"""
    f = open(file_path, mode)
    try:
        if os.name == 'posix':
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        yield f
    finally:
        if os.name == 'posix':
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        f.close()


@app.post("/api/shorten")
async def shorten_url(request: fastapi.Request):
    try:
        request_body = await request.json()
    except Exception:
        return fastapi.responses.JSONResponse(status_code=400, content={"error": "Invalid JSON body"})
    
    origin = request_body.get("origin", "")
    url = request_body.get("url", "")
    
    # Validate URL format
    if not url or not validate_url(url):
        return fastapi.responses.JSONResponse(status_code=400, content={"error": "Invalid URL format. Must be a valid HTTP/HTTPS URL."})
    
    # Validate origin
    if not origin or not validate_url(origin):
        return fastapi.responses.JSONResponse(status_code=400, content={"error": "Invalid origin URL."})
    
    try:
        with file_lock("urls.txt", "r+") as linkfile:
            links = linkfile.readlines()
            if any(url in line for line in links):
                return fastapi.responses.JSONResponse(status_code=400, content={"error": "URL already shortened"})
            
            # Generate unique ID with secure random
            unique_id = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(6))
            random_word = random.choice(random_words)
            unique_id = random_word + unique_id[:3]
            share_path = f"{origin}/{unique_id}"
            
            if any(share_path in line for line in links):
                return fastapi.responses.JSONResponse(status_code=400, content={"error": "URL taken. Please try again."})
            
            linkfile.write(f"{share_path};{url}\n")
        
        return fastapi.responses.JSONResponse(status_code=201, content={"url": share_path, "original_url": url})
    except FileNotFoundError:
        # Create file if it doesn't exist
        try:
            with open("urls.txt", "w") as f:
                pass
            return await shorten_url(request)  # Retry
        except Exception as e:
            logger.error(f"Failed to create urls.txt: {e}")
            return fastapi.responses.JSONResponse(status_code=500, content={"error": "Service configuration error"})
    except Exception as e:
        logger.error(f"Error shortening URL: {e}")
        return fastapi.responses.JSONResponse(status_code=500, content={"error": "Internal server error"})


def stipFFmpegDebug(line):
    """
    Entfernt sensible Pfade und Usernamen aus einer FFmpeg-Debug-Zeile.
    """
    # Windows-Pfade (z.B. C:\Users\jason\... oder D:\irgendwas\...)
    line = re.sub(r"[A-Za-z]:\\(?:[^\\\s]+\\)*[^\\\s]*", "<PATH>", line)
    # Unix-Pfade (z.B. /home/user/..., /tmp/..., /irgendwas)
    line = re.sub(r"/(?:[^/\s]+/)*[^/\s]*", "<PATH>", line)
    # Usernamen in Windows-Pfaden maskieren (z.B. C:\Users\jason -> C:\Users\<USER>)
    line = re.sub(r"C:\\Users\\[^\\\s]+", r"C:\\Users\\<USER>", line)
    # Usernamen in Linux-Pfaden maskieren (z.B. /home/jason -> /home/<USER>)
    line = re.sub(r"/home/[^/\s]+", r"/<USER>/", line)
    # Usernamen in /root/... Pfaden maskieren (z.B. /root/.cache -> /root/<USER>)
    line = re.sub(r"/root/[^/\s]+", r"/<USER>/", line)
    return line


def ffmpeg_convert(input_path, output_path, share_path):
    q = conversion_progress[share_path]
    cmd = [
        "ffmpeg",
        "-analyzeduration", "100M",
        "-probesize", "100M",
        "-y",
        "-i", input_path,
        output_path
    ]
    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    duration = None
    for line in process.stderr:
        clean_line = stipFFmpegDebug(line)
        print(line, end="")  # Print FFmpeg output live to console
        # Gesamtdauer extrahieren
        if duration is None:
            match = re.search(r"Duration: (\d+):(\d+):(\d+\.\d+)", line)
            if match:
                h, m, s = match.groups()
                duration = int(h) * 3600 + int(m) * 60 + float(s)
        # Fortschritt extrahieren
        match = re.search(r"time=(\d+):(\d+):(\d+\.\d+)", line)
        if match and duration:
            h, m, s = match.groups()
            current = int(h) * 3600 + int(m) * 60 + float(s)
            percent = (current / duration) * 100
            eta = (duration - current)
            # Fortschritt in Queue speichern
            q.put({"percent": percent, "eta": eta,
                  "debug": clean_line, "finished": False})
    process.wait()
    q.put({"percent": 100, "eta": 0, "finished": True, "share_path": share_path})


async def appendToUserFiles(req: fastapi.Request, share_url: str, filename: str, expireAt = None):
    auth = req.headers.get("Authorization")
    if not auth:
        return
    auth_status = await get_auth_status(req)
    if not auth_status:
        return
    db = None
    try:
        db = await get_db()
        session_key = auth
        result = await db.query("SELECT * FROM users WHERE $session_key INSIDE session_keys", {"session_key": session_key})
        users = result[0].get("result", [])
        if not users:
            return
        user = users[0]
        
        # Migrate user schema if needed (preserves files)
        user = await migrate_user_schema(db, user)
        
        user_files = user.get("files", [])
        if not isinstance(user_files, list):
            user_files = []
        if not expireAt or expireAt == "permanent":
            expireAt = "NULL"
        if isinstance(expireAt, str) and expireAt != "permanent" and expireAt != "NULL":
            expireAt = float(expireAt)
        user_files.append({
            "share_url": share_url, 
            "filename": filename,
            "expireAt": expireAt
        })
        await db.query("UPDATE users SET files = $files WHERE username = $username", {
            "files": user_files,
            "username": user["username"],
        })
    except Exception as e:
        logger.error(f"Failed to append to user files: {e}")
        return None
    finally:
        if db:
            await release_db(db)

async def get_user_files(req: fastapi.Request):
    auth = req.headers.get("Authorization")
    if not auth:
        return fastapi.responses.JSONResponse(status_code=401, content={"error": "Unauthorized"})
    auth_status = await get_auth_status(req)
    logging.debug(f"[Auth] Status: {auth_status}")
    if not auth_status:
        return fastapi.responses.JSONResponse(status_code=401, content={"error": "Unauthorized"})
    db = None
    try:
        db = await get_db()
        session_key = auth
        result = await db.query("SELECT * FROM users WHERE $session_key INSIDE session_keys", {"session_key": session_key})
        users = result[0].get("result", [])
        if not users:
            return fastapi.responses.JSONResponse(status_code=404, content={"error": "User not found"})
        user = users[0]
        
        # Migrate user schema if needed (preserves files)
        user = await migrate_user_schema(db, user)
        
        user_files = user.get("files", [])
        if not isinstance(user_files, list):
            user_files = []
        return fastapi.responses.JSONResponse(status_code=200, content={"files": user_files})
    except Exception as e:
        logger.error(f"get_user_files error: {e}")
        return safe_error_response(500, "Failed to retrieve files", str(e))
    finally:
        if db:
            await release_db(db)

@app.post("/api/convert")
async def convert_to_share(
    request: fastapi.Request,
    file: UploadFile = File(...),
    output_ext: str = Form(...),
    origin: str = Form(None),
    auth_status: bool = Depends(get_auth_status)
):
    # Validate output format against whitelist (prevent command injection)
    output_ext_clean = output_ext.lower().strip().lstrip('.')
    if output_ext_clean not in ALLOWED_CONVERSION_FORMATS:
        return JSONResponse(
            status_code=400, 
            content={"error": f"Invalid output format '{output_ext}'. Allowed formats: {', '.join(sorted(ALLOWED_CONVERSION_FORMATS))}"}
        )
    output_ext = output_ext_clean  # Use sanitized version
    
    form = await request.form()
    permanent = form.get("permanent") == "true"
    if auth_status and isinstance(auth_status, dict):
        is_auth = auth_status.get("auth", False)
    else:
        is_auth = bool(auth_status)
    if is_auth is False and "Authorization" in request.headers:
        # Invalid session key was sent → return 401
        return JSONResponse(status_code=401, content={"error": "Invalid session key"})
    
    # Get file manager
    fm = get_file_manager()
    
    random_word = random.choice(random_words)
    input_filename = file.filename
    filename_wo_ext = ".".join(input_filename.strip().split(".")[
                               :-1]) or input_filename
    # Ziel-Dateiname und Pfad
    logging.info(
        f"Converting file: {input_filename} to {output_ext} with permanent={permanent}")
    
    # Use FileManager to get paths
    output_file_path = fm.get_conversion_output_path(filename_wo_ext, output_ext, permanent=permanent)
    share_path = f"{random_word}/{filename_wo_ext}.{output_ext}"
    input_file_path = fm.get_conversion_input_path(input_filename)

    with open(input_file_path, "wb") as f:
        f.write(await file.read())
    # Fortschritts-Queue anlegen
    q = queue.Queue()
    conversion_progress[share_path] = q
    logging.info(f"Conversion progress updated: {conversion_progress}")

    # FFmpeg-Konvertierung im Thread starten
    threading.Thread(target=ffmpeg_convert, args=(
        input_file_path, output_file_path, share_path), daemon=True).start()
    file_url = f"{origin}/u/{random_word}/{filename_wo_ext}.{output_ext}"
    # Speichere permanent-Flag in files.txt
    if permanent:
        if not is_auth:
            return fastapi.responses.JSONResponse(status_code=401, content={"error": "Unauthorized: Permanent conversion requires login"})
        with open("files.txt", "a+") as file_file:
            file_file.write(f"{file_url};{output_file_path};permanent\n")
    else:
        expire_ts = int(time.time()) + 60*60*24*90
        with open("files.txt", "a+") as file_file:
            file_file.write(f"{file_url};{output_file_path};expire={expire_ts}\n")
    response_content = {"share_url": file_url,
                        "share_path": share_path, "conversion_started": True}
    if is_auth:
        response_content["auth"] = "true"
    if permanent:
        response_content["permanent"] = "true"
    await appendToUserFiles(request, share_url=file_url, filename=f"{filename_wo_ext}.{output_ext}", expireAt=expire_ts if not permanent else "permanent")
    return fastapi.responses.JSONResponse(
        status_code=201,
        content=response_content
    )


@app.get("/api/convert_progress/{share_path:path}")
async def convert_progress(share_path: str, auth_status: bool = Depends(get_auth_status)):
    if "%2F" in share_path:
        share_path = share_path.replace("%2F", "/")

    async def event_generator():
        q = conversion_progress.get(share_path)
        if not q:
            yield f"data: {json.dumps({'percent': 0, 'eta': None, 'error': 'No conversion'})}\n\n"
            return
        while True:
            try:
                progress = q.get(timeout=30)
                if auth_status:
                    progress["auth"] = True
                yield f"data: {json.dumps(progress)}\n\n"
                if progress.get("finished"):
                    break
            except queue.Empty:
                break
    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.delete("/{share_path}")
def delete_share(share_path: str):
    shares_file = open("shares.json", "r")
    shares = json.load(shares_file)

    if share_path in shares:
        del shares[share_path]
        shares_file = open("shares.json", "w")
        json.dump(shares, shares_file)
        shares_file.close()
        return fastapi.responses.JSONResponse(status_code=200, content={"message": "Share deleted", "share_path": share_path})
    else:
        return fastapi.responses.JSONResponse(status_code=404, content={"error": "Share not found"})


@app.get("/webinterface/create.js")
def render_create_js():
    if not os.path.exists(f"{pathlib.Path(__file__).parent.resolve()}/webinterface/create.js"):
        return fastapi.responses.JSONResponse(status_code=404, content={"error": "create.js not found"})
    # Serve the create.js file from the webinterface directory
    return fastapi.responses.FileResponse(f"{pathlib.Path(__file__).parent.resolve()}/webinterface/create.js")


@app.get("/webinterface/{errorsound}")
def render_errorsound(errorsound: str):
    if errorsound not in ["Error 1.mp3", "Error 2.mp3", "Error 3.mp3",
                          "Error 4.mp3", "Error 5.mp3", "Error 6.mp3",
                          "Error 7.mp3", "Error 8.mp3", "Error 9.mp3", "Error 10.mp3"]:
        return fastapi.responses.JSONResponse(status_code=404, content={"detail": "Not found"})
    sound_path = f"{pathlib.Path(__file__).parent.resolve()}/webinterface/{errorsound}"
    if not os.path.exists(sound_path):
        return fastapi.responses.JSONResponse(status_code=404, content={"error": "Sound file does not exist"})
    # Serve the sound file from the webinterface directory
    return fastapi.responses.FileResponse(sound_path)


@app.get("/u/{random_word}/{file_path}")
def download_file(random_word: str, file_path: str, download: bool = False):
    # Sanitize inputs to prevent path traversal
    random_word = sanitize_filename(random_word)
    file_path = sanitize_filename(file_path)
    
    if not random_word or not file_path:
        return fastapi.responses.JSONResponse(status_code=400, content={"error": "Invalid file path"})
    
    combined_path = random_word + "/" + file_path
    
    try:
        with open("files.txt", "r") as files_file:
            files = files_file.readlines()
    except FileNotFoundError:
        logger.error("files.txt not found")
        return fastapi.responses.JSONResponse(status_code=500, content={"error": "Service configuration error"})
    except Exception as e:
        logger.error(f"Error reading files.txt: {e}")
        return fastapi.responses.JSONResponse(status_code=500, content={"error": "Internal server error"})
    
    for file in files:
        file = file.strip()
        if combined_path in file:
            file_parts = file.split(";")
            if len(file_parts) < 2:
                continue
            file_path_on_disk = file_parts[1]
            
            # Verify path is within allowed directory
            fm = get_file_manager()
            upload_dir = os.path.abspath(fm.get_upload_directory())
            resolved_path = os.path.abspath(file_path_on_disk)
            
            if not resolved_path.startswith(upload_dir):
                logger.warning(f"Path traversal attempt detected: {file_path_on_disk}")
                return fastapi.responses.JSONResponse(status_code=403, content={"error": "Access denied"})
            
            if not os.path.exists(file_path_on_disk):
                return fastapi.responses.JSONResponse(status_code=404, content={"error": "File not found"})
            
            try:
                mimetype, _ = mimetypes.guess_type(file_path_on_disk)
                if download:
                    return fastapi.responses.FileResponse(
                        path=file_path_on_disk,
                        media_type=mimetype,
                        filename=os.path.basename(file_path_on_disk),
                        headers={
                            "Content-Disposition": f'attachment; filename="{os.path.basename(file_path_on_disk)}"'}
                    )
                else:
                    with open(file_path_on_disk, "rb") as f:
                        file_content = f.read()
                    return fastapi.responses.Response(content=file_content, media_type=mimetype)
            except Exception as e:
                logger.error(f"Error serving file {file_path_on_disk}: {e}")
                return fastapi.responses.JSONResponse(status_code=500, content={"error": "Error serving file"})
    
    return fastapi.responses.JSONResponse(status_code=404, content={"error": "File not found"})


@app.post("/api/upload")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    auth_status: bool = Depends(get_auth_status)
):
    # Get file manager
    fm = get_file_manager()
    
    try:
        form = await request.form()
        logging.debug(f"Permanent flag: {form.get('permanent')}")
        permanent = form.get("permanent") == "true"
        filename = (file.filename or "").strip()
        if not filename:
            return JSONResponse(status_code=400, content={"error": "No filename provided"})
        
        # Sanitize filename to prevent path traversal
        filename = sanitize_filename(filename)
        if not filename:
            return JSONResponse(status_code=400, content={"error": "Invalid filename after sanitization"})
        
        # Validate file extension
        ext_valid, ext_error = validate_file_extension(filename)
        if not ext_valid:
            return JSONResponse(status_code=400, content={"error": ext_error})
        
        # Validate filename using FileManager
        is_valid, error_msg = fm.validate_filename(filename, allow_permanent_prefix=False)
        if not is_valid:
            return JSONResponse(status_code=400, content={"error": error_msg})
        
        # Validate file size from content-length header
        content_length = request.headers.get("content-length")
        if content_length:
            size_mb = int(content_length) / (1024 * 1024)
            if size_mb > config.MAX_REQUEST_SIZE_MB:
                return JSONResponse(status_code=413, content={"error": f"File too large. Maximum size is {config.MAX_REQUEST_SIZE_MB} MB"})
        
        unique_id = secrets.token_urlsafe(6)
        origin = request.headers.get("origin", "")
        random_word = random.choice(random_words)
        file_url = f"{origin}/u/{random_word}/{filename}"
        
        # Use FileManager to get path
        file_path = fm.get_file_path(filename, permanent=permanent)
        
        # Read file content with size limit
        file_content = await file.read()
        
        # Prüfe permanent-Flag
        if permanent:
            if not auth_status:
                return JSONResponse(status_code=401, content={"error": "Unauthorized: Permanent upload requires login"})
            
            try:
                with file_lock("files.txt", "a+") as file_file:
                    file_file.write(f"{file_url};{file_path};permanent\\n")
            except Exception as e:
                logger.error(f"Error writing to files.txt: {e}")
                return JSONResponse(status_code=500, content={"error": "Failed to register file"})
            
            try:
                with open(file_path, "wb") as file_object:
                    file_object.write(file_content)
            except Exception as e:
                logger.error(f"Error writing file {file_path}: {e}")
                return JSONResponse(status_code=500, content={"error": "Failed to save file"})
            
            response_content = {"url": file_url,
                                "original_filename": filename, "permanent": True}
            if auth_status:
                response_content["auth"] = "true"
            expire_at = "permanent"
        else:
            # Ablaufdatum: 3 Monate ab jetzt
            expire_ts = int(time.time()) + 60*60*24*90
            
            try:
                with file_lock("files.txt", "a+") as file_file:
                    file_file.write(f"{file_url};{file_path};expire={expire_ts}\\n")
            except Exception as e:
                logger.error(f"Error writing to files.txt: {e}")
                return JSONResponse(status_code=500, content={"error": "Failed to register file"})
            
            try:
                with open(file_path, "wb") as file_object:
                    file_object.write(file_content)
            except Exception as e:
                logger.error(f"Error writing file {file_path}: {e}")
                return JSONResponse(status_code=500, content={"error": "Failed to save file"})
            
            response_content = {"url": file_url, "original_filename": filename}
            if auth_status:
                response_content["auth"] = "true"
            expire_at = expire_ts
        
        # Append to user files
        await appendToUserFiles(request, share_url=file_url, filename=filename, expireAt=expire_at)
        return JSONResponse(status_code=201, content=response_content)
    except Exception as e:
        logger.error(f"Upload error: {e}")
        return JSONResponse(status_code=500, content={"error": "Upload failed"})


@app.get("/user/login")
async def render_login_webinterface(login_password: Optional[str] = None):
    if not timing_safe_compare(login_password or "", config.LOGIN_PASSWORD):
        return fastapi.responses.JSONResponse(status_code=404, content={"detail": "Not found"})
    with open("./webinterface/login.html", "r", encoding="utf-8") as f:
        return fastapi.responses.HTMLResponse(content=f.read())


@app.post("/user/login")
async def user_login(request: Request, login_password: Optional[str] = None):
    if not timing_safe_compare(login_password or "", config.LOGIN_PASSWORD):
        return fastapi.responses.JSONResponse(status_code=404, content={"detail": "Not found"})
    body = await request.json()
    username = body.get("username", "").strip()
    password = body.get("password", "")
    if not username or not password:
        return fastapi.responses.JSONResponse(status_code=400, content={"error": "Username and password required"})
    
    # Check for account lockout
    current_time = time.time()
    lockout_window = current_time - ACCOUNT_LOCKOUT_DURATION
    failed_login_attempts[username] = [
        ts for ts in failed_login_attempts[username] if ts > lockout_window
    ]
    
    if len(failed_login_attempts[username]) >= ACCOUNT_LOCKOUT_THRESHOLD:
        remaining = int(ACCOUNT_LOCKOUT_DURATION - (current_time - failed_login_attempts[username][0]))
        logger.warning(f"Account locked out: {username}")
        return fastapi.responses.JSONResponse(
            status_code=429, 
            content={"error": f"Account temporarily locked. Try again in {remaining // 60} minutes."}
        )
    
    db = None
    try:
        db = await get_db()
        result = await db.query("SELECT * FROM users WHERE username = $username", {"username": username})
        users = result[0].get("result", [])
        if not users:
            # Record failed attempt and use generic message
            failed_login_attempts[username].append(current_time)
            return fastapi.responses.JSONResponse(status_code=401, content={"error": "Invalid username or password (0x49554E)"})
        user = users[0]
        
        # Migrate user schema if needed (preserves files)
        user = await migrate_user_schema(db, user)
        
        if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            # Record failed attempt
            failed_login_attempts[username].append(current_time)
            logger.warning(f"Failed login attempt for user: {username}")
            return fastapi.responses.JSONResponse(status_code=401, content={"error": "Invalid username or password (0x495057)"})
        
        # Clear failed attempts on successful login
        failed_login_attempts[username] = []
        
        # Generate cryptographically secure session key
        session_key = generate_secure_token(64)
        session_keys = user.get("session_keys", [])
        session_data = user.get("session_data", {})
        if not isinstance(session_keys, list):
            session_keys = []
        if not isinstance(session_data, dict):
            session_data = {}
        
        # Limit number of active sessions per user
        if len(session_keys) >= config.MAX_SESSIONS_PER_USER:
            # Remove oldest sessions
            oldest_key = session_keys[0]
            session_keys = session_keys[-(config.MAX_SESSIONS_PER_USER - 1):]
            if oldest_key in session_data:
                del session_data[oldest_key]
        
        session_keys.append(session_key)
        session_data[session_key] = {
            "created_at": current_time,
            "ip": request.client.host if request.client else "unknown",
            "user_agent": request.headers.get("User-Agent", "unknown")[:200]
        }
        
        await db.query(
            "UPDATE users SET session_keys = $keys, session_data = $data, last_login = $login_time WHERE username = $username", 
            {"keys": session_keys, "data": session_data, "login_time": current_time, "username": username}
        )
        
        logger.info(f"User '{username}' logged in successfully")
        return fastapi.responses.JSONResponse(status_code=200, content={"session_key": session_key})
    except Exception as e:
        logger.error(f"Login error: {e}")
        return safe_error_response(500, "Authentication failed", str(e))
    finally:
        if db:
            await release_db(db)


@app.get("/user/auth")
async def user_auth(request: fastapi.Request):
    return await get_auth_status(request)


@app.get("/user/logout")
async def render_logout_webinterface():
    with open("./webinterface/logout.html", "r", encoding="utf-8") as f:
        return fastapi.responses.HTMLResponse(content=f.read())


@app.post("/user/logout")
async def user_logout(request: Request):
    """Invalidate the current session."""
    session_key = request.headers.get("Authorization")
    if not session_key:
        return JSONResponse(status_code=400, content={"error": "No session key provided"})
    
    db = None
    try:
        db = await get_db()
        
        result = await db.query("SELECT * FROM users WHERE $session_key INSIDE session_keys", {"session_key": session_key})
        users = result[0].get("result", [])
        
        if not users:
            return JSONResponse(status_code=200, content={"message": "Logged out"})
        
        user = users[0]
        session_keys = user.get("session_keys", [])
        session_data = user.get("session_data", {})
        
        if session_key in session_keys:
            session_keys.remove(session_key)
        if isinstance(session_data, dict) and session_key in session_data:
            del session_data[session_key]
        
        await db.query(
            "UPDATE users SET session_keys = $keys, session_data = $data WHERE username = $username",
            {"keys": session_keys, "data": session_data, "username": user["username"]}
        )
        
        logger.info(f"User '{user['username']}' logged out")
        return JSONResponse(status_code=200, content={"message": "Logged out successfully"})
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return JSONResponse(status_code=200, content={"message": "Logged out"})
    finally:
        if db:
            await release_db(db)


@app.get("/user/signup")
async def render_signup_webinterface(login_password: Optional[str] = None):
    if not timing_safe_compare(login_password or "", config.LOGIN_PASSWORD):
        return fastapi.responses.JSONResponse(status_code=404, content={"detail": "Not found"})
    with open("./webinterface/signup.html", "r", encoding="utf-8") as f:
        return fastapi.responses.HTMLResponse(content=f.read())


@app.post("/user/signup")
async def user_signup(request: fastapi.Request, login_password: Optional[str] = None):
    if not timing_safe_compare(login_password or "", config.LOGIN_PASSWORD):
        return fastapi.responses.JSONResponse(status_code=404, content={"detail": "Not found"})
    body = await request.body()
    if not body:
        return fastapi.responses.JSONResponse(status_code=400, content={"error": "No data provided"})
    if not request.headers.get("Content-Type") == "application/json":
        return fastapi.responses.JSONResponse(status_code=400, content={"error": "Content-Type must be application/json"})
    try:
        data = json.loads(body)
    except Exception:
        return fastapi.responses.JSONResponse(status_code=400, content={"error": "Invalid JSON"})

    username = data.get("username", "").strip().lower()
    password = data.get("password", "")

    if not username or not password:
        return fastapi.responses.JSONResponse(status_code=400, content={"error": "Username and password cannot be empty"})
    
    # Validate password strength
    is_valid_password, password_error = validate_password_strength(password)
    if not is_valid_password:
        return fastapi.responses.JSONResponse(status_code=400, content={"error": password_error})
    
    # Validate username format
    if not re.match(r'^[a-zA-Z0-9_-]{3,32}$', username):
        return fastapi.responses.JSONResponse(status_code=400, content={"error": "Username must be 3-32 characters and contain only letters, numbers, underscores, and hyphens"})
    
    db = None
    try:
        db = await get_db()

        # Check if user already exists (using parameterized query to prevent SQL injection)
        existing_user = await db.query("SELECT * FROM users WHERE username = $username", {"username": username})
        if existing_user[0]['result']:
            return fastapi.responses.JSONResponse(status_code=409, content={"error": "Username already exists"})

        # Hash the password with configurable work factor
        hashed_password = bcrypt.hashpw(password.encode(
            'utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')

        # Create new user (using parameterized query to prevent SQL injection)
        await db.query("INSERT INTO users (username, password, created_at) VALUES ($username, $password, $created_at)", {
            "username": username,
            "password": hashed_password,
            "created_at": time.time()
        })

        logger.info(f"New user created: {username}")
        return fastapi.responses.JSONResponse(status_code=201, content={"message": "User created successfully"})

    except Exception as e:
        logger.error(f"Signup error: {e}")
        return safe_error_response(500, "Account creation failed", str(e))
    finally:
        if db:
            await release_db(db)


@app.get("/api/users/me")
async def get_current_user(request: fastapi.Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return fastapi.responses.JSONResponse(status_code=401, content={"error": "Unauthorized"})
    session_key = auth_header.split(" ")[-1]
    db = None
    try:
        db = await get_db()

        # Query user by session key
        user = await db.query("SELECT * FROM users WHERE $session_key INSIDE session_keys", {"session_key": session_key})
        if not user[0]['result']:
            return fastapi.responses.JSONResponse(status_code=404, content={"error": "User not found"})

        user_data = user[0]['result'][0]
        # Remove sensitive information
        user_data.pop("password", None)
        user_data.pop("session_key", None)

        return fastapi.responses.JSONResponse(status_code=200, content=user_data)

    except Exception as e:
        logger.error(f"Get current user error: {e}")
        return safe_error_response(500, "Failed to retrieve user data", str(e))
    finally:
        if db:
            await release_db(db)


@app.get("/login/oauth")
def render_oauth_webinterface():
    with open("./webinterface/oauth.html", "r", encoding="utf-8") as f:
        return fastapi.responses.HTMLResponse(content=f.read())


# In-memory storage for OAuth codes (expires after 5 minutes)
oauth_codes = {}

@app.post("/api/oauth/generate-code")
async def oauth_generate_code(request: Request):
    """Generate an OAuth code for a client application"""
    try:
        body = await request.json()
        app_name = body.get("app_name", "Unknown App")
        redirect_uri = body.get("redirect_uri")
        
        if not redirect_uri:
            return JSONResponse(status_code=400, content={"error": "Missing redirect_uri"})
        
        # Validate redirect_uri is a valid URL
        if not validate_url(redirect_uri):
            return JSONResponse(status_code=400, content={"error": "Invalid redirect_uri format"})
        
        # Generate a cryptographically secure code
        code = generate_secure_token(32)
        
        # Store code with metadata (expires in 5 minutes)
        oauth_codes[code] = {
            "app_name": app_name,
            "redirect_uri": redirect_uri,
            "created_at": time.time(),
            "used": False
        }
        
        return JSONResponse(status_code=200, content={
            "code": code,
            "auth_url": f"https://s.jesn.zip/login/oauth?code={code}&app={app_name}&redirect_uri={redirect_uri}"
        })
    except Exception as e:
        logger.error(f"Generate Code Error: {e}")
        return JSONResponse(status_code=500, content={"error": "Internal Server Error"})


@app.post("/api/oauth/authorize")
async def oauth_authorize(request: Request):
    auth = request.headers.get("Authorization")
    if not auth:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})
    
    try:
        body = await request.json()
        code = body.get("code")
        
        if not code:
             return JSONResponse(status_code=400, content={"error": "Missing code"})
        
        # Check if code exists and is valid
        if code not in oauth_codes:
            return JSONResponse(status_code=404, content={"error": "Invalid code"})
        
        code_data = oauth_codes[code]
        
        # Check if code is expired (5 minutes)
        if time.time() - code_data["created_at"] > 300:
            del oauth_codes[code]
            return JSONResponse(status_code=400, content={"error": "Code expired"})
        
        # Check if code was already used
        if code_data["used"]:
            return JSONResponse(status_code=400, content={"error": "Code already used"})

        db = None
        try:
            db = await get_db()
            
            # Verify user
            result = await db.query("SELECT * FROM users WHERE $session_key INSIDE session_keys", {"session_key": auth})
            users = result[0].get("result", [])
            if not users:
                return JSONResponse(status_code=401, content={"error": "Invalid session"})
            
            user = users[0]
            
            # Migrate user schema if needed (preserves files)
            user = await migrate_user_schema(db, user)
            
            # Generate cryptographically secure OAuth token
            oauth_token = generate_secure_token(64)
            
            # Store token in user record with code reference
            current_tokens = user.get("oauth_tokens", {})
            if not isinstance(current_tokens, dict):
                current_tokens = {}
            
            current_tokens[oauth_token] = {
                "code": code,
                "app_name": code_data["app_name"],
                "created_at": time.time()
            }
            
            await db.query("UPDATE users SET oauth_tokens = $tokens WHERE id = $id", {
                "tokens": current_tokens,
                "id": user["id"]
            })
            
            # Mark code as used
            oauth_codes[code]["used"] = True
            
            # Construct redirect URL
            redirect_uri = code_data["redirect_uri"]
            separator = "&" if "?" in redirect_uri else "?"
            redirect_url = f"{redirect_uri}{separator}token={oauth_token}"
            
            return JSONResponse(status_code=200, content={"redirect_url": redirect_url})
        finally:
            if db:
                await release_db(db)

    except Exception as e:
        logger.error(f"OAuth Error: {e}")
        return JSONResponse(status_code=500, content={"error": "Internal Server Error"})


@app.get("/api/oauth/verify")
async def oauth_verify(token: str):
    if not token:
        return JSONResponse(status_code=400, content={"error": "Missing token"})
    
    db = None
    try:
        db = await get_db()
        
        # Find user with this token (using parameterized query)
        result = await db.query("SELECT * FROM users WHERE oauth_tokens CONTAINS $token", {"token": token})
        users = result[0].get("result", [])
        
        if not users:
            return JSONResponse(status_code=404, content={"valid": False, "error": "Invalid token"})
            
        user = users[0]
        
        # Check if token exists in user's oauth_tokens
        oauth_tokens = user.get("oauth_tokens", {})
        if not isinstance(oauth_tokens, dict) or token not in oauth_tokens:
            return JSONResponse(status_code=401, content={"valid": False, "error": "Invalid token"})
        
        return JSONResponse(status_code=200, content={
            "valid": True,
            "username": user.get("username"),
            "session_key": token
        })
        
    except Exception as e:
        logger.error(f"OAuth Verify Error: {e}")
        return JSONResponse(status_code=500, content={"error": "Internal Server Error"})
    finally:
        if db:
            await release_db(db)

@app.get("/user/files")
async def user_files(request: fastapi.Request):
    return await get_user_files(request)


@app.delete("/user/files")
async def delete_user_files(request: fastapi.Request, auth_status: bool = Depends(get_auth_status)):
    if not auth_status:
        return fastapi.responses.JSONResponse(status_code=401, content={"error": "Unauthorized"})
    body = await request.json()
    if not body:
        return fastapi.responses.JSONResponse(status_code=400, content={"error": "No data provided"})
    if not request.headers.get("Content-Type") == "application/json":
        return fastapi.responses.JSONResponse(status_code=400, content={"error": "Content-Type must be application/json"})
    if "share_url" not in body.keys():
        return fastapi.responses.JSONResponse(status_code=400, content={"error": "share_url is required"})
    share_url = body.get("share_url")
    share_url = share_url.replace("%20", " ")  # Replace %20 with space
    if not share_url:
        return fastapi.responses.JSONResponse(status_code=400, content={"error": "share_url cannot be empty"})
    
    db = None
    try:
        db = await get_db()
        session_key = request.headers.get("Authorization")
        result = await db.query("SELECT * FROM users WHERE $session_key INSIDE session_keys", {"session_key": session_key})
        users = result[0].get("result", [])
        if not users:
            return fastapi.responses.JSONResponse(status_code=404, content={"error": "User not found"})
        user = users[0]
        
        # Migrate user schema if needed (preserves files)
        user = await migrate_user_schema(db, user)
        
        user_files = user.get("files", [])
        if not isinstance(user_files, list):
            user_files = []
        before_user_files = user_files.copy()
        for file in user_files:
            if file.get("share_url") == share_url:
                user_files.remove(file)
        if user_files == before_user_files:
            return fastapi.responses.JSONResponse(status_code=404, content={"error": "File not found in user files"})
        await db.query("UPDATE users SET files = $files WHERE username = $username", {
            "files": user_files,
            "username": user["username"]
        })
        return fastapi.responses.JSONResponse(status_code=200, content={"message": "User files deleted"})
    except Exception as e:
        logger.error(f"delete_user_files error: {e}")
        return safe_error_response(500, "Failed to delete files", str(e))
    finally:
        if db:
            await release_db(db)

async def get_remaining_storage():
    fm = get_file_manager()
    upload_dir = fm.get_upload_directory()
    total, used, free = shutil.disk_usage(upload_dir)
    return free // (2**30)  # Return free space in GB

@app.get("/misc/storage")
async def get_storage_info(request: fastapi.Request, auth_status: bool = Depends(get_auth_status)):
    if not auth_status:
        return fastapi.responses.JSONResponse(status_code=401, content={"error": "Unauthorized"})
    free_gb = await get_remaining_storage()
    return fastapi.responses.JSONResponse(status_code=200, content={"free_gb": free_gb})


@app.get("/api/config/upload-directory")
async def get_upload_directory_endpoint(request: Request, auth_status: bool = Depends(get_auth_status)):
    """Get current upload directory configuration."""
    if not auth_status:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})
    
    # Admin password must be in header, not query string (security)
    admin_password = request.headers.get("X-Admin-Password", "")
    if not timing_safe_compare(admin_password, config.ADMIN_PASSWORD):
        return JSONResponse(status_code=403, content={"error": "Forbidden"})

    fm = get_file_manager()
    return JSONResponse(status_code=200, content={
        "upload_directory": fm.get_upload_directory(),
        "permanent_prefix": fm.permanent_prefix,
        "conversion_input_prefix": fm.conversion_input_prefix
    })


@app.post("/api/config/upload-directory")
async def change_upload_directory_endpoint(
    request: Request,
    auth_status: bool = Depends(get_auth_status)
):
    """Change upload directory dynamically."""
    if not auth_status:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})
    
    # Admin password must be in header, not query string (security)
    admin_password = request.headers.get("X-Admin-Password", "")
    if not timing_safe_compare(admin_password, config.ADMIN_PASSWORD):
        return JSONResponse(status_code=403, content={"error": "Forbidden"})
    try:
        body = await request.json()
        new_directory = body.get("directory")
        
        if not new_directory:
            return JSONResponse(status_code=400, content={"error": "Directory path is required"})
        
        success, error_msg = set_upload_directory(new_directory)
        
        if success:
            return JSONResponse(status_code=200, content={
                "message": "Upload directory changed successfully",
                "new_directory": new_directory
            })
        else:
            return JSONResponse(status_code=400, content={
                "error": f"Failed to change directory: {error_msg}"
            })
    except Exception as e:
        return JSONResponse(status_code=500, content={
            "error": "Internal server error",
            "details": str(e)
        })


@app.get("/api/files/list")
async def list_files_endpoint(
    auth_status: bool = Depends(get_auth_status),
    permanent_only: bool = False,
    exclude_conversion: bool = True
):
    """List files in the upload directory."""
    if not auth_status:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})
    
    fm = get_file_manager()
    files = fm.list_files(permanent_only=permanent_only, exclude_conversion_inputs=exclude_conversion)
    
    # Add file details
    file_details = []
    for filename in files:
        size = fm.get_file_size(filename)
        is_permanent = fm.is_permanent_file(filename)
        file_details.append({
            "filename": filename,
            "size": size,
            "is_permanent": is_permanent
        })
    
    return JSONResponse(status_code=200, content={
        "files": file_details,
        "count": len(file_details)
    })


# ==================== Account & Session Management ====================

@app.get("/user/account")
async def user_account_page(request: Request):
    """Serve the account management page."""
    return FileResponse("webinterface/account.html")


@app.get("/api/user/sessions")
async def get_user_sessions(request: Request):
    """Get all sessions for the authenticated user."""
    session_key = request.headers.get("Authorization")
    
    if not session_key:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})
    
    db = None
    try:
        db = await get_db()
        
        # Find user with this session key
        result = await db.query("SELECT * FROM users WHERE $session_key INSIDE session_keys", {"session_key": session_key})
        users = result[0].get("result", [])
        if not users:
            return JSONResponse(status_code=401, content={"error": "Invalid session"})
        
        user = users[0]
        
        # Migrate user schema if needed (preserves files)
        user = await migrate_user_schema(db, user)
        
        user_session_data = user.get("session_data", {})
        
        # Check if current session is expired
        if isinstance(user_session_data, dict) and session_key in user_session_data:
            created_at = user_session_data[session_key].get("created_at", 0)
            expiry_seconds = config.SESSION_EXPIRY_HOURS * 3600
            if time.time() - created_at > expiry_seconds:
                return JSONResponse(status_code=401, content={"error": "Session expired"})
        
        # Build sessions list from user's session data
        sessions = []
        for key, data in user_session_data.items():
            if isinstance(data, dict):
                session_entry = {
                    "session_id": key[:8] + "..." + key[-4:],  # Truncated for display
                    "is_current": timing_safe_compare(key, session_key),
                    "created_at": data.get("created_at", 0),
                    "ip": data.get("ip", "Unknown"),
                    "user_agent": data.get("user_agent", "Unknown")
                }
                sessions.append(session_entry)
        
        # Sort by creation time, newest first
        sessions.sort(key=lambda x: x["created_at"], reverse=True)
        
        return JSONResponse(status_code=200, content={"sessions": sessions})
        
    except Exception as e:
        logger.error(f"Get Sessions Error: {e}")
        return JSONResponse(status_code=500, content={"error": "Internal Server Error"})
    finally:
        if db:
            await release_db(db)


@app.delete("/api/user/sessions")
async def revoke_sessions(request: Request):
    """Revoke one or more sessions. Requires password confirmation."""
    current_session_key = request.headers.get("Authorization")
    
    if not current_session_key:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})
    
    try:
        body = await request.json()
        password = body.get("password")
        session_id = body.get("session_id")  # Truncated ID or None for all
        revoke_all = body.get("revoke_all", False)
        
        if not password:
            return JSONResponse(status_code=400, content={"error": "Password required"})
        
        db = await get_db()
        
        # Find user with this session key
        result = await db.query("SELECT * FROM users WHERE $session_key INSIDE session_keys", {"session_key": current_session_key})
        users = result[0].get("result", [])
        if not users:
            return JSONResponse(status_code=401, content={"error": "Invalid session"})
        
        user = users[0]
        
        # Migrate user schema if needed (preserves files)
        user = await migrate_user_schema(db, user)
        
        # Verify password
        if not bcrypt.checkpw(password.encode(), user["password"].encode()):
            return JSONResponse(status_code=403, content={"error": "Invalid password"})
        
        session_keys = user.get("session_keys", [])
        user_session_data = user.get("session_data", {})
        revoked_count = 0
        
        if revoke_all:
            # Revoke all sessions except current
            keys_to_keep = [current_session_key]
            data_to_keep = {current_session_key: user_session_data.get(current_session_key, {})}
            revoked_count = len(session_keys) - 1
            session_keys = keys_to_keep
            user_session_data = data_to_keep
        elif session_id:
            # Find and revoke specific session by truncated ID
            session_to_remove = None
            for key in session_keys:
                truncated = key[:8] + "..." + key[-4:]
                if truncated == session_id:
                    session_to_remove = key
                    break
            
            if session_to_remove:
                # Don't allow revoking current session through this endpoint
                if timing_safe_compare(session_to_remove, current_session_key):
                    return JSONResponse(status_code=400, content={
                        "error": "Cannot revoke current session. Use logout instead."
                    })
                session_keys.remove(session_to_remove)
                if session_to_remove in user_session_data:
                    del user_session_data[session_to_remove]
                revoked_count = 1
            else:
                return JSONResponse(status_code=404, content={"error": "Session not found"})
        else:
            return JSONResponse(status_code=400, content={
                "error": "Specify session_id or set revoke_all to true"
            })
        
        # Update database
        await db.query(
            "UPDATE users SET session_keys = $keys, session_data = $data WHERE username = $username",
            {"keys": session_keys, "data": user_session_data, "username": user["username"]}
        )
        
        logger.info(f"Revoked {revoked_count} session(s) for user {user['username']}")
        return JSONResponse(status_code=200, content={
            "success": True,
            "revoked_count": revoked_count
        })
        
    except json.JSONDecodeError:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON"})
    except Exception as e:
        logger.error(f"Revoke Sessions Error: {e}")
        return JSONResponse(status_code=500, content={"error": "Internal Server Error"})
    finally:
        if db:
            await release_db(db)


# ============== Change Username ==============
@app.put("/api/user/username")
async def change_username(request: Request):
    """Change the current user's username"""
    try:
        # Validate session
        auth_status = await get_auth_status(request)
        if not auth_status["authenticated"]:
            return JSONResponse(status_code=401, content={"error": "Not authenticated"})
        
        # Parse request body
        body = await request.json()
        new_username = body.get("new_username", "").strip()
        
        # Validate new username
        if not new_username:
            return JSONResponse(status_code=400, content={"error": "Username cannot be empty"})
        
        if len(new_username) < 3:
            return JSONResponse(status_code=400, content={"error": "Username must be at least 3 characters"})
        
        if len(new_username) > 32:
            return JSONResponse(status_code=400, content={"error": "Username cannot exceed 32 characters"})
        
        # Only allow alphanumeric, underscore, dash
        import re
        if not re.match(r'^[a-zA-Z0-9_-]+$', new_username):
            return JSONResponse(status_code=400, content={
                "error": "Username can only contain letters, numbers, underscores, and dashes"
            })
        
        db = await get_db()
        current_username = auth_status["username"]
        
        # Check if new username is same as current
        if new_username.lower() == current_username.lower():
            return JSONResponse(status_code=400, content={"error": "This is already your username"})
        
        # Check if username is already taken (case-insensitive)
        existing = await db.query(
            "SELECT * FROM users WHERE string::lowercase(username) = string::lowercase($username)",
            {"username": new_username}
        )
        if existing and existing[0] and len(existing[0]) > 0:
            return JSONResponse(status_code=409, content={"error": "Username is already taken"})
        
        # Update username in database
        await db.query(
            "UPDATE users SET username = $new_username WHERE username = $current_username",
            {"new_username": new_username, "current_username": current_username}
        )
        
        logger.info(f"Username changed from {current_username} to {new_username}")
        return JSONResponse(status_code=200, content={
            "success": True,
            "message": "Username changed successfully",
            "new_username": new_username
        })
        
    except json.JSONDecodeError:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON"})
    except Exception as e:
        logger.error(f"Change Username Error: {e}")
        return JSONResponse(status_code=500, content={"error": "Internal Server Error"})


# ============== Change Password ==============
@app.put("/api/user/password")
async def change_password(request: Request):
    """Change the current user's password (requires current password verification)"""
    try:
        # Validate session
        auth_status = await get_auth_status(request)
        if not auth_status:
            return JSONResponse(status_code=401, content={"error": "Not authenticated"})
        
        # Parse request body
        body = await request.json()
        current_password = body.get("current_password", "")
        new_password = body.get("new_password", "")
        confirm_password = body.get("confirm_password", "")

        if await get_auth_status(request, check_password=current_password) is False:
            return JSONResponse(status_code=403, content={"error": "Current password is incorrect"})
        
        # Validate inputs
        if not current_password:
            return JSONResponse(status_code=400, content={"error": "Current password is required"})
        
        if not new_password:
            return JSONResponse(status_code=400, content={"error": "New password is required"})
        
        if new_password != confirm_password:
            return JSONResponse(status_code=400, content={"error": "New passwords do not match"})
        
        if len(new_password) < 8:
            return JSONResponse(status_code=400, content={"error": "New password must be at least 8 characters"})
        
        if len(new_password) > 128:
            return JSONResponse(status_code=400, content={"error": "New password cannot exceed 128 characters"})
        
        db = await get_db()
        username = auth_status["username"]
        
        # Get user from database
        result = await db.query(
            "SELECT * FROM users WHERE username = $username",
            {"username": username}
        )
        
        if not result or not result[0]:
            return JSONResponse(status_code=404, content={"error": "User not found"})
        
        user = result[0][0] if isinstance(result[0], list) else result[0]
        
        # Verify current password
        if not bcrypt.checkpw(current_password.encode(), user["password"].encode()):
            logger.warning(f"Failed password change attempt for user {username} - incorrect current password")
            return JSONResponse(status_code=403, content={"error": "Current password is incorrect"})
        
        # Hash new password
        new_password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
        
        # Update password in database
        await db.query(
            "UPDATE users SET password = $password WHERE username = $username",
            {"password": new_password_hash, "username": username}
        )
        
        logger.info(f"Password changed for user {username}")
        return JSONResponse(status_code=200, content={
            "success": True,
            "message": "Password changed successfully"
        })
        
    except json.JSONDecodeError:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON"})
    except Exception as e:
        logger.error(f"Change Password Error: {e}")
        return JSONResponse(status_code=500, content={"error": "Internal Server Error"})


def check_upload_worker():
    while True:
        try:
            files_file = open("files.txt", "r")
            files = files_file.readlines()
            files_file.close()
            updated_files = []
            for file in files:
                file = file.strip()
                if not file:  # Skip empty lines
                    continue
                
                logging.debug(f"[FileChecker] Checking file: {file}")
                
                # Initialize file_path to None
                file_path = None
                
                try:
                    parts = file.split(";")
                    if len(parts) < 2:
                        logging.error(f"[FileChecker] Invalid file format (missing parts): {file}")
                        continue
                    
                    file_path = parts[1]
                    
                    # Check if file exists
                    if not os.path.exists(file_path):
                        logging.warning(f"[FileChecker] File does not exist, removing from list: {file_path}")
                        continue
                    
                    # Check expiration
                    if len(parts) > 2:
                        expire_info = parts[2]
                        if "expire=" in expire_info:
                            try:
                                expire_ts = int(expire_info.split("=")[1])
                                if expire_ts < int(time.time()):
                                    logging.info(f"[FileChecker] File expired, deleting: {file_path}")
                                    os.remove(file_path)
                                    continue
                            except (ValueError, IndexError) as e:
                                logging.error(f"[FileChecker] Invalid expire timestamp in: {file} - {e}")
                        elif expire_info.strip() == "permanent":
                            # Permanent file, keep it
                            updated_files.append(file + "\n")
                            continue
                    
                    # File is valid and not expired, keep it
                    updated_files.append(file + "\n")
                    
                except Exception as e:
                    logging.error(f"[FileChecker] Failed to check file: {file}")
                    logging.error(f"[FileChecker] Error: {e}")
                    # If we have a file_path and can't determine status, keep it to be safe
                    if file_path:
                        updated_files.append(file + "\n")
            
            # Write updated file list
            with file_lock("files.txt", "w") as files_file:
                files_file.writelines(updated_files)
            
            logging.info(f"[FileChecker] Check complete. {len(updated_files)} files remaining.")
            time.sleep(300)
        except Exception as e:
            logging.error(f"[FileChecker] Critical error: {e}")
            import traceback
            traceback.print_exc()
            time.sleep(60)


def check_db_connection():
    """Background worker to periodically check database connectivity"""
    import asyncio
    loop = None
    while True:
        try:
            # Reuse event loop if possible to avoid issues
            try:
                loop = asyncio.get_event_loop()
                if loop.is_closed():
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            
            loop.run_until_complete(test_db_connection())
        except Exception as e:
            logging.error(f"[DB] Database connection check failed: {e}")
        time.sleep(60)  # Check every minute

async def test_db_connection():
    """Test database connectivity and clear stale connections from pool"""
    db = None
    try:
        # Create a fresh connection for testing (bypass pool)
        db = Surreal(config.DATABASE_URL)
        await db.connect()
        await db.signin({"user": config.DATABASE_USER, "pass": config.DATABASE_PASSWORD})
        await db.use(config.NAMESPACE_NAME, config.DATABASE_NAME)
        await db.query("SELECT * FROM users LIMIT 1")
        logging.info("[DB] Connection successful")
        await db.close()
        return True
    except Exception as e:
        logging.error(f"[DB] Database connection failed: {e}")
        # Try to clear the pool on failure
        if db_pool:
            try:
                while not db_pool._pool.empty():
                    try:
                        stale_db = db_pool._pool.get_nowait()
                        await db_pool._close_connection(stale_db)
                    except:
                        pass
                logging.info("[DB] Cleared stale connections from pool")
            except:
                pass
        return False
    finally:
        if db:
            try:
                await db.close()
            except:
                pass

def check_required_directories():
    required_dirs = [
        config.UPLOAD_DIRECTORY
    ]
    for directory in required_dirs:
        if not os.path.exists(directory):
            try:
                os.makedirs(directory)
                logging.info(f"Created missing directory: {directory}")
            except Exception as e:
                logging.error(f"Failed to create directory {directory}: {e}")
                raise

def check_reuired_sub_programs():
    required_programs = [
        "ffmpeg",
        "ffprobe",
        "pdftoppm",
    ]
    for program in required_programs:
        if not shutil.which(program):
            logging.error(f"Required program '{program}' is not installed or not in PATH.\nUse --install-deps to automatically install missing dependencies (Linux only).")
            raise Exception(f"Required program '{program}' is not installed or not in PATH")


def start_workers():
    threading.Thread(target=check_required_directories, daemon=True).start()
    threading.Thread(target=check_reuired_sub_programs, daemon=True).start()
    threading.Thread(target=check_upload_worker, daemon=True).start()
    threading.Thread(target=check_db_connection, daemon=True).start()


if __name__ == "__main__":
    start_workers()
    logger.info(f"Starting server on {config.SERVER_HOST}:{config.SERVER_PORT}")
    uvicorn.run(app, host=config.SERVER_HOST, port=config.SERVER_PORT)
