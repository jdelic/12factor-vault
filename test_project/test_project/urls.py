from django.db import connection
from django.http import HttpRequest, JsonResponse
from django.urls import path


def whoami(request: HttpRequest) -> JsonResponse:
    with connection.cursor() as cursor:
        cursor.execute("SELECT session_user, current_user")
        session_user, current_user = cursor.fetchone()
    return JsonResponse({"session_user": session_user, "current_user": current_user})


urlpatterns = [
    path("whoami/", whoami),
]
