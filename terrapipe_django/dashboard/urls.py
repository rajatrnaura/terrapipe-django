# urls.py (add this to your URLs configuration)
from django.urls import path
from .views import get_user_geoids , login

urlpatterns = [
    path('login/', login, name='login'),
    path('get-user-geoids/', get_user_geoids, name='get_user_geoids'),
]