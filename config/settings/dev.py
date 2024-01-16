from .base import *
import dj_database_url

EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

DATABASES = {
    'default': dj_database_url.parse(os.getenv('DATABASE_URL'), conn_max_age=600)
}
DATABASES["default"]["ATOMIC_REQUESTS"] = True
