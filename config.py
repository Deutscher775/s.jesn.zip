"""
Configuration module - Uses environment variables for deployment.
All values must be set in .env file or environment variables.
"""
import os

# Load .env file if it exists
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, skip

# check if .env file exists (just print warning, don't fail)
if not os.path.exists(".env"):
    import sys
    current_dir = os.getcwd()
    print(f"Warning: .env file not found in {current_dir}. Using environment variables from system.", file=sys.stderr)


def get_env(key: str) -> str:
    """Get environment variable or raise error if not set."""
    value = os.environ.get(key)
    if value is None or value == "":
        raise EnvironmentError(f"Required environment variable '{key}' is not set")
    return value


def get_env_int(key: str) -> int:
    """Get environment variable as integer."""
    return int(get_env(key))


def get_env_bool(key: str) -> bool:
    """Get environment variable as boolean."""
    return get_env(key).lower() == "true"


def get_env_list(key: str) -> list:
    """Get environment variable as comma-separated list."""
    return get_env(key).split(",")


# Environment mode
ENVIRONMENT = get_env("ENVIRONMENT")
IS_PRODUCTION = ENVIRONMENT.lower() == "production"

# Database configuration
DATABASE_URL = get_env("DATABASE_URL")
DATABASE_NAME = get_env("DATABASE_NAME")
NAMESPACE_NAME = get_env("NAMESPACE_NAME")
DATABASE_USER = get_env("DATABASE_USER")
DATABASE_PASSWORD = get_env("DATABASE_PASSWORD")

# Administrative settings
ADMIN_PASSWORD = get_env("ADMIN_PASSWORD")

# Login configuration
LOGIN_PASSWORD = get_env("LOGIN_PASSWORD")

# File storage configuration
UPLOAD_DIRECTORY = get_env("UPLOAD_DIRECTORY")

# File prefixes
PERMANENT_FILE_PREFIX = get_env("PERMANENT_FILE_PREFIX")
CONVERSION_INPUT_PREFIX = get_env("CONVERSION_INPUT_PREFIX")

# Security settings
ALLOWED_ORIGINS = get_env_list("ALLOWED_ORIGINS")
SESSION_EXPIRY_HOURS = get_env_int("SESSION_EXPIRY_HOURS")
MAX_SESSIONS_PER_USER = get_env_int("MAX_SESSIONS_PER_USER")
MAX_REQUEST_SIZE_MB = get_env_int("MAX_REQUEST_SIZE_MB")

# Rate limiting
RATE_LIMIT_REQUESTS = get_env_int("RATE_LIMIT_REQUESTS")
RATE_LIMIT_WINDOW_SECONDS = get_env_int("RATE_LIMIT_WINDOW_SECONDS")

# Password requirements
MIN_PASSWORD_LENGTH = get_env_int("MIN_PASSWORD_LENGTH")
REQUIRE_PASSWORD_SPECIAL_CHAR = get_env_bool("REQUIRE_PASSWORD_SPECIAL_CHAR")
REQUIRE_PASSWORD_NUMBER = get_env_bool("REQUIRE_PASSWORD_NUMBER")
REQUIRE_PASSWORD_UPPERCASE = get_env_bool("REQUIRE_PASSWORD_UPPERCASE")

# Allowed file extensions for upload
ALLOWED_EXTENSIONS = get_env_list("ALLOWED_EXTENSIONS")

# Blocked file extensions (security)
BLOCKED_EXTENSIONS = get_env_list("BLOCKED_EXTENSIONS")

# Account Lockout Settings
ACCOUNT_LOCKOUT_THRESHOLD = get_env_int("ACCOUNT_LOCKOUT_THRESHOLD") if os.environ.get("ACCOUNT_LOCKOUT_THRESHOLD") else 5
ACCOUNT_LOCKOUT_DURATION = get_env_int("ACCOUNT_LOCKOUT_DURATION") if os.environ.get("ACCOUNT_LOCKOUT_DURATION") else 900

# Server Configuration
SERVER_HOST = os.environ.get("SERVER_HOST", "0.0.0.0")
SERVER_PORT = int(os.environ.get("SERVER_PORT", "9941"))

# OAuth Settings
OAUTH_CODE_EXPIRY_SECONDS = int(os.environ.get("OAUTH_CODE_EXPIRY_SECONDS", "300"))

# Database Pool Size
DB_POOL_SIZE = int(os.environ.get("DB_POOL_SIZE", "10"))
