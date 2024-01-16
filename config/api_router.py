from rest_framework.routers import DefaultRouter, SimpleRouter
from django.conf import settings
from api.views.authentication_views import AuthenticationViewSet

if settings.DEBUG:
    router = DefaultRouter()
else:
    router = SimpleRouter()

router.register("authentication", AuthenticationViewSet, basename="authentication viewsets")

app_name = "api"
urlpatterns = router.urls
