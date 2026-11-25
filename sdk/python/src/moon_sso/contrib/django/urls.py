"""Include with ``path("auth/", include("moon_sso.contrib.django.urls"))``."""

from django.urls import path

from . import views

app_name = "moon_sso"

urlpatterns = [
    path("login", views.login, name="login"),
    path("callback", views.callback, name="callback"),
    path("logout", views.logout, name="logout"),
    path("webhook", views.webhook, name="webhook"),
    path("backchannel-logout", views.backchannel_logout, name="backchannel_logout"),
]
