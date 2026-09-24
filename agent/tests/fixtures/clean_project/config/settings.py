from pathlib import Path
BASE_DIR = Path(__file__).resolve().parents[1]
RUNTIME = BASE_DIR / 'runtime'
SECRET_KEY = (RUNTIME / 'keys' / 'django.key').read_text().strip()
DATA_KEY_FILE = RUNTIME / 'keys' / 'data.key'
LOG_KEY_FILE = RUNTIME / 'keys' / 'journal.key'
DEBUG = False
ALLOWED_HOSTS = ['127.0.0.1', 'localhost']
INSTALLED_APPS = ['django.contrib.auth', 'django.contrib.contenttypes', 'django.contrib.sessions', 'app.apps.AppConfig']
MIDDLEWARE = ['django.middleware.security.SecurityMiddleware', 'django.contrib.sessions.middleware.SessionMiddleware', 'django.middleware.csrf.CsrfViewMiddleware', 'django.contrib.auth.middleware.AuthenticationMiddleware', 'app.middleware.AuditMiddleware']
ROOT_URLCONF = 'config.urls'
AUTH_USER_MODEL = 'app.User'
DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': RUNTIME / 'db.sqlite3'}}
PASSWORD_HASHERS = ['django.contrib.auth.hashers.Argon2PasswordHasher']
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 12}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]
SESSION_COOKIE_AGE = 3600
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
LOGGING = {'version': 1, 'handlers': {'null': {'class': 'logging.NullHandler'}}, 'loggers': {'django': {'handlers': ['null']}}}
