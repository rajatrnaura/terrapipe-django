# urls.py (add this to your URLs configuration)
from django.urls import path
from .views import get_user_geoids ,login,  get_user_geoids_with_details , products , products_page , login_page , asset_map_view , get_geoids , get_field_boundary , logout_view , delete_field , get_user_scope , get_coordinates , scope_map
urlpatterns = [
    path('login/', login, name='login'),
    path('get-user-geoids/', get_user_geoids_with_details, name='get_user_geoids'),
    path('', login_page, name='login_page'),
    path('products/', products, name='products'),
    path('products_page/', products_page, name='products_page'),
    path("asset_map/", asset_map_view, name="asset_map_page"),
    path("geoids/", get_geoids, name="api_geoids"),
    path("field-boundary/<str:geoid>/", get_field_boundary, name="api_field_boundary"),
    path('logout/', logout_view, name='logout_api'),
    path('delete-field/<str:field_id>/', delete_field, name='delete_field'),
    path('scope_map/', scope_map, name='scope_map'),
    path('get_user_scope/', get_user_scope, name='get_user_scope'),
    path('get_coordinates/<str:scope>/', get_coordinates, name='get_coordinates')

]