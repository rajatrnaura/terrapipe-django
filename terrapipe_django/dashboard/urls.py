# urls.py (add this to your URLs configuration)
from django.urls import path
from .views import get_user_geoids ,login,  get_user_geoids_with_details , products , products_page , login_page , map_view , get_geoids , get_field_boundary , logout_view
urlpatterns = [
    path('login/', login, name='login'),
    path('get-user-geoids/', get_user_geoids_with_details, name='get_user_geoids'),
    path('', login_page, name='login_page'),
    path('products/', products, name='products'),
    path('products_page/', products_page, name='products_page'),
    path("map/", map_view, name="map_page"),
    path("geoids/", get_geoids, name="api_geoids"),
    path("field-boundary/<str:geoid>/", get_field_boundary, name="api_field_boundary"),
    path('api/logout/', logout_view, name='logout_api')
]