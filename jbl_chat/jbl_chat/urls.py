from django.urls import path

import chat.views as views


urlpatterns = [
    path("", views.IndexView.as_view(), name="index"),
    path(
        "conversation/<str:username>",
        views.ConversationView.as_view(),
        name="conversation"
    ),
    path("api/login", views.LoginAPIView.as_view(), name="login-api"),
    path("api/logout", views.LogoutAPIView.as_view(), name="logout-api"),
    path(
        "api/message/<int:partner_user_id>",
        views.MessageAPIView.as_view(),
        name="message-api"
    ),
    path(
        "api/user/<int:user_id>",
        views.UserDetailAPIView.as_view(),
        name="user-detail-api"
    ),
]
