import os

from dotenv import load_dotenv


load_dotenv()


# --------------------------------------------------
# Helpers
# --------------------------------------------------

def env_bool(name: str, default: bool = False) -> bool:
    """Read a boolean value from the environment."""
    return os.getenv(
        name,
        str(default),
    ).lower() in (
        "true",
        "1",
        "yes",
        "on",
    )


# --------------------------------------------------
# Application
# --------------------------------------------------

APP_NAME = os.getenv(
    "APP_NAME",
    "BugHunter ADK",
)

VERSION = os.getenv(
    "VERSION",
    "0.6.0"
)

MODEL = os.getenv(
    "MODEL",
    "gemini-2.5-flash",
)

DEBUG = env_bool(
    "DEBUG",
    False,
)

LOG_LEVEL = os.getenv(
    "LOG_LEVEL",
    "INFO",
)


# --------------------------------------------------
# Database
# --------------------------------------------------

DATABASE = os.getenv(
    "DATABASE",
    "database/bughunter.db",
)


# --------------------------------------------------
# API Keys
# --------------------------------------------------

GOOGLE_API_KEY = os.getenv(
    "GOOGLE_API_KEY",
    "",
)

OTX_API_KEY = os.getenv(
    "OTX_API_KEY",
    "",
)

SHODAN_API_KEY = os.getenv(
    "SHODAN_API_KEY",
    "",
)

SECURITYTRAILS_API_KEY = os.getenv(
    "SECURITYTRAILS_API_KEY",
    "",
)

CENSYS_API_ID = os.getenv(
    "CENSYS_API_ID",
    "",
)

CENSYS_API_SECRET = os.getenv(
    "CENSYS_API_SECRET",
    "",
)

VIRUSTOTAL_API_KEY = os.getenv(
    "VIRUSTOTAL_API_KEY",
    "",
)

URLSCAN_API_KEY = os.getenv(
    "URLSCAN_API_KEY",
    "",
)


# --------------------------------------------------
# Scanner
# --------------------------------------------------

MAX_WORKERS = int(
    os.getenv(
        "MAX_WORKERS",
        "20",
    )
)

REQUEST_TIMEOUT = int(
    os.getenv(
        "REQUEST_TIMEOUT",
        "20",
    )
)

HTTP_TIMEOUT = int(
    os.getenv(
        "HTTP_TIMEOUT",
        "20",
    )
)

TLS_TIMEOUT = int(
    os.getenv(
        "TLS_TIMEOUT",
        "10",
    )
)

DNS_TIMEOUT = int(
    os.getenv(
        "DNS_TIMEOUT",
        "5",
    )
)


# --------------------------------------------------
# HTTP
# --------------------------------------------------

USER_AGENT = os.getenv(
    "USER_AGENT",
    "BugHunterADK/1.0",
)

VERIFY_SSL = env_bool(
    "VERIFY_SSL",
    True,
)

FOLLOW_REDIRECTS = env_bool(
    "FOLLOW_REDIRECTS",
    True,
)


# --------------------------------------------------
# Katana
# --------------------------------------------------

KATANA_TIMEOUT = int(
    os.getenv(
        "KATANA_TIMEOUT",
        "15",
    )
)

KATANA_DEPTH = int(
    os.getenv(
        "KATANA_DEPTH",
        "1",
    )
)

KATANA_CONCURRENCY = int(
    os.getenv(
        "KATANA_CONCURRENCY",
        "5",
    )
)


# --------------------------------------------------
# Passive Recon
# --------------------------------------------------

ENABLE_WAYBACK = env_bool(
    "ENABLE_WAYBACK",
    True,
)

ENABLE_COMMONCRAWL = env_bool(
    "ENABLE_COMMONCRAWL",
    True,
)

ENABLE_OTX = env_bool(
    "ENABLE_OTX",
    True,
)


# --------------------------------------------------
# JavaScript
# --------------------------------------------------

MAX_JS_FILES = int(
    os.getenv(
        "MAX_JS_FILES",
        "500",
    )
)

MAX_JS_FILE_SIZE = int(
    os.getenv(
        "MAX_JS_FILE_SIZE",
        str(5 * 1024 * 1024),
    )
)


# --------------------------------------------------
# AI
# --------------------------------------------------

ENABLE_AI = env_bool(
    "ENABLE_AI",
    True,
)

AI_SUMMARY = env_bool(
    "AI_SUMMARY",
    True,
)


# --------------------------------------------------
# Reporting
# --------------------------------------------------

SAVE_JSON = env_bool(
    "SAVE_JSON",
    True,
)

SAVE_HTML = env_bool(
    "SAVE_HTML",
    True,
)

SAVE_CSV = env_bool(
    "SAVE_CSV",
    False,
)

SAVE_MARKDOWN = env_bool(
    "SAVE_MARKDOWN",
    True,
)


# --------------------------------------------------
# Screenshots
# --------------------------------------------------

ENABLE_SCREENSHOTS = env_bool(
    "ENABLE_SCREENSHOTS",
    False,
)

SCREENSHOT_TIMEOUT = int(
    os.getenv(
        "SCREENSHOT_TIMEOUT",
        "15",
    )
)


# --------------------------------------------------
# Nuclei
# --------------------------------------------------

ENABLE_NUCLEI = env_bool(
    "ENABLE_NUCLEI",
    False,
)

NUCLEI_SEVERITY = os.getenv(
    "NUCLEI_SEVERITY",
    "critical,high,medium",
)

# --------------------------------------------------
# retry session count
# --------------------------------------------------

CONNECT_TIMEOUT = int(
    os.getenv(
        "CONNECT_TIMEOUT",
        "10",
    )
)

RETRY_COUNT = int(
    os.getenv(
        "RETRY_COUNT",
        "3",
    )
)   

RETRY_BACKOFF = float(
    os.getenv(
        "RETRY_BACKOFF",
        "1.0",
    )
)   

SUBFINDER_TIMEOUT = int(
    os.getenv(
        "SUBFINDER_TIMEOUT",
        "60",
    )
)

SUBFINDER_RECURSIVE = env_bool(
    "SUBFINDER_RECURSIVE",
    True,
)