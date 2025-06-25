# urls.py (add this to your URLs configuration)
from django.urls import path
from .views import *

urlpatterns = [
    path('login/', login, name='login'),
    path('get-user-geoids/', get_user_geoids_with_details, name='get_user_geoids'),
    path('register-field-boundary/', register_field_boundary, name='register_field_boundary'),
    path('map/', map_view, name='map'),
]