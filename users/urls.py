from django.urls import path
from rest_framework.authtoken.views import obtain_auth_token
from . import views

urlpatterns = [
    path("", views.Users.as_view()),
    path("me", views.Me.as_view()),
    path("login", views.LogIn.as_view()),
    path("logout", views.LogOut.as_view()),
    path("token-login", obtain_auth_token),
    path("jwt-login", views.JWTLogIn.as_view()),
    path("@<str:username>", views.PublicUser.as_view()),
    path("view", views.UserView.as_view()),
    path("delete", views.UserDelete.as_view()),
    path("update", views.UserUpdate.as_view()),
]