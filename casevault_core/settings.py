"""
Django settings for CaseVault project.
Organization: Northbridge Cyber Response
Module: CYS22301 Software and Platform Security (Level 6)
Standards: ADR-0001 through ADR-0006
"""

import os
import secrets
import urllib.parse
from pathlib import Path

from dotenv import load_dotenv

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables from .env file
load_dotenv(BASE_DIR / '.env')

# Security-critical environment configurations
ENVIRONMENT = os.environ.get('CASEVAULT_ENV', 'development')
DEBUG = os.environ.get('DEBUG', 'False').lower() in ('true', '1', 'yes')

SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')
if not SECRET_KEY:
    if DEBUG:
        # Generate ephemeral random key in memory for isolated development session
        SECRET_KEY = secrets.token_urlsafe(64)
    else:
        raise ValueError("CRITICAL SECURITY ERROR: DJANGO_SECRET_KEY is not defined in production environment!")

# Allowed Hosts & CSRF Origins
ALLOWED_HOSTS = [h.strip() for h in os.environ.get('ALLOWED_HOSTS', 'localhost,127.0.0.1,[::1],app,nginx').split(',') if h.strip()]
CSRF_TRUSTED_ORIGINS = [o.strip() for o in os.environ.get('CSRF_TRUSTED_ORIGINS', 'http://localhost:8000,http://127.0.0.1:8000,https://localhost,https://127.0.0.1').split(',') if o.strip()]

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Security Infrastructure Apps (Technology Decisions)
    'axes',
    'django_otp',
    'django_otp.plugins.otp_totp',

    # CaseVault Domain Apps
    'core',
    'accounts',
    'cases',
    'vault',
    'audit',
]

AUTHENTICATION_BACKENDS = [
    'axes.backends.AxesStandaloneBackend',
    'django.contrib.auth.backends.ModelBackend',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django_otp.middleware.OTPMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',

    # Custom Security Headers & CSP (django-csp)
    'core.middleware.SecurityHeadersMiddleware',
    'csp.middleware.CSPMiddleware',
    'core.middleware.MFAEnforcementMiddleware',

    # Brute-force lockout middleware (django-axes)
    'axes.middleware.AxesMiddleware',
]

ROOT_URLCONF = 'casevault_core.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'csp.context_processors.nonce',
                'core.context_processors.csp_nonce',
            ],
        },
    },
]

WSGI_APPLICATION = 'casevault_core.wsgi.application'

# ==============================================================================
# Database Configuration (PostgreSQL 16 in Docker, SQLite fallback for unit tests)
# ==============================================================================
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL and (DATABASE_URL.startswith('postgres://') or DATABASE_URL.startswith('postgresql://')):
    url = urllib.parse.urlparse(DATABASE_URL)
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': url.path[1:],
            'USER': url.username,
            'PASSWORD': url.password,
            'HOST': url.hostname,
            'PORT': url.port or 5432,
            'OPTIONS': {
                'sslmode': os.environ.get('POSTGRES_SSLMODE', 'prefer'),
            }
        }
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'casevault_dev.sqlite3',
        }
    }

# Custom User Model with RBAC Roles
AUTH_USER_MODEL = 'accounts.CustomUser'

# ==============================================================================
# Cryptographic Password Hashing (ADR-0001: Argon2id)
# ==============================================================================
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.Argon2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
]

# Password Validation (NIST SP 800-63B: minimum length 12)
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {'min_length': 12},
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# ==============================================================================
# Session & Cookie Hardening
# ==============================================================================
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_AGE = int(os.environ.get('SESSION_COOKIE_AGE', 900))  # 15 minutes
SESSION_EXPIRE_AT_BROWSER_CLOSE = os.environ.get('SESSION_EXPIRE_AT_BROWSER_CLOSE', 'True').lower() in ('true', '1')

CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'

# Production SSL / Transport Security
SECURE_SSL_REDIRECT = os.environ.get('SECURE_SSL_REDIRECT', 'False').lower() in ('true', '1')
SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() in ('true', '1')
CSRF_COOKIE_SECURE = os.environ.get('CSRF_COOKIE_SECURE', 'False').lower() in ('true', '1')

if SECURE_SSL_REDIRECT:
    SECURE_HSTS_SECONDS = 31536000  # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True

# ==============================================================================
# Content Security Policy (django-csp with per-request nonces, no unsafe-inline)
# ==============================================================================
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)
CSP_STYLE_SRC = ("'self'", "https://fonts.googleapis.com")
CSP_FONT_SRC = ("'self'", "https://fonts.gstatic.com", "data:")
CSP_IMG_SRC = ("'self'", "data:")
CSP_OBJECT_SRC = ("'none'",)
CSP_BASE_URI = ("'self'",)
CSP_FORM_ACTION = ("'self'",)
CSP_FRAME_ANCESTORS = ("'none'",)
CSP_INCLUDE_NONCE_IN = ['script-src', 'style-src']

# ==============================================================================
# Rate Limiting & Account Lockout (django-axes)
# ==============================================================================
AXES_FAILURE_LIMIT = 5
AXES_COOLOFF_TIME = 0.25  # 15 minutes
AXES_RESET_ON_SUCCESS = True
AXES_LOCKOUT_TEMPLATE = 'accounts/lockout.html'
AXES_VERBOSE = True

# Internationalization
LANGUAGE_CODE = 'en-gb'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = 'static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ==============================================================================
# CaseVault Security Keys & Storage Paths
# ==============================================================================
CASEVAULT_EVIDENCE_KEY = os.environ.get('CASEVAULT_EVIDENCE_KEY', '')
CASEVAULT_AUDIT_HMAC_KEY = os.environ.get('CASEVAULT_AUDIT_HMAC_KEY', '')

# Isolated evidence filesystem storage (outside web server document root)
EVIDENCE_STORAGE_PATH = Path(os.environ.get('EVIDENCE_STORAGE_PATH', BASE_DIR / 'vault_storage')).resolve()
EVIDENCE_STORAGE_PATH.mkdir(parents=True, exist_ok=True)

# Authentication Routing
LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'case_list'
LOGOUT_REDIRECT_URL = 'login'

# Maximum upload size: 25 Megabytes
DATA_UPLOAD_MAX_MEMORY_SIZE = 26214400
FILE_UPLOAD_MAX_MEMORY_SIZE = 26214400

# ==============================================================================
# Secure Logging Configuration (Satisfies Hard Rule #5)
# ==============================================================================
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'filters': {
        'sensitive_data_filter': {
            '()': 'core.middleware.SensitiveDataLoggingFilter',
        },
    },
    'formatters': {
        'secure_verbose': {
            'format': '[{asctime}] {levelname} [{name}] {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'secure_verbose',
            'filters': ['sensitive_data_filter'],
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'axes': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'casevault': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}
