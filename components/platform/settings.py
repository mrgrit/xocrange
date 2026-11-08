"""Unix-socket-only management application; no forwarded identity is trusted."""
import json
import os
from pathlib import Path

CONFIG = json.loads(Path(os.environ.get('XOC_PLATFORM_CONFIG', '/run/xoc-platform/config.json')).read_text())
SECRET_KEY = CONFIG['secret_key']
DEBUG = False
ALLOWED_HOSTS = ['platform', CONFIG['public_host']]
ROOT_URLCONF = 'control.urls'
INSTALLED_APPS = ['django.contrib.auth', 'django.contrib.contenttypes', 'django.contrib.sessions', 'control']
MIDDLEWARE = ['django.middleware.security.SecurityMiddleware', 'django.contrib.sessions.middleware.SessionMiddleware',
              'django.contrib.auth.middleware.AuthenticationMiddleware', 'control.middleware.Boundary',
              'django.middleware.csrf.CsrfViewMiddleware', 'django.middleware.clickjacking.XFrameOptionsMiddleware']
DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': CONFIG.get('database', '/var/lib/xoc-platform/control.sqlite3'),
                         'OPTIONS': {'timeout': 20, 'transaction_mode': 'IMMEDIATE'}}}
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
USE_TZ = True
TIME_ZONE = 'UTC'
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_NAME = '__Host-xoc_session'
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_AGE = 900
SESSION_SAVE_EVERY_REQUEST = True
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
CSRF_COOKIE_NAME = '__Host-xoc_csrf'
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'
CSRF_TRUSTED_ORIGINS = ['https://' + CONFIG['public_host']]
CSRF_FAILURE_VIEW = 'control.views.csrf_failure'
# The only management listener is a volume-mounted Unix socket shared with WAF.
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
DATA_UPLOAD_MAX_MEMORY_SIZE = 16384
DATA_UPLOAD_MAX_NUMBER_FIELDS = 30
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 14}},
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]
TEMPLATES = [{'BACKEND': 'django.template.backends.django.DjangoTemplates', 'APP_DIRS': True}]
# Never emit request bodies, query strings, cookies, passwords or tracebacks.
LOGGING = {'version': 1, 'disable_existing_loggers': True,
           'handlers': {'null': {'class': 'logging.NullHandler'}},
           'root': {'handlers': ['null'], 'level': 'CRITICAL'}}
