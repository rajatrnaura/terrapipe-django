# urls.py (add this to your URLs configuration)
from django.urls import path
from .views import *

urlpatterns = [
    path('login/', login, name='login'),
    path('logout/', logout_view, name='logout_api'),
    path('get-user-geoids/', get_user_geoids_with_details, name='get_user_geoids'),
    path('register-field-boundary/', register_field_boundary, name='register_field_boundary'),
    path('', login_page, name='login_page'),
    path('map/', map_view, name='map'),
    path('products/', products, name='products'),
    path('products_page/', products_page, name='products_page'),
    path("asset_map/", asset_map_view, name="asset_map_page"),
    path("geoids/", get_geoids, name="api_geoids"),
    path("field-boundary/<str:geoid>/", get_field_boundary, name="api_field_boundary"),
    path('logout/', logout_view, name='logout_api'),
    path('delete-field/<str:field_id>/', delete_field, name='delete_field'),
    path('scope_map/', scope_map, name='scope_map'),
    path('get_user_scope/', get_user_scope, name='get_user_scope'),
    path('get_coordinates/<str:scope>/', get_coordinates, name='get_coordinates'),
    path("getScopesBB/", get_scopes_bb, name="get_scopes_bb"),
    path("request-activation/", request_activation, name="request_activation"),
    path("remove_scope/", remove_scope, name="remove_scope"),
    path("add_user_scope/", add_user_scope, name="add_user_scope"),
    path("fetch-field-bb/", fetch_field_bb, name="fetch_field_bb"),
    path("forgot_password_page/", forgot_password_page, name="forgot_password_page"),
    path("forgot_password", forgot_password, name="forgot_password"),
    path("register", signup_page, name="signup_page"),
    path("signup", signup, name="signup"),
    
]