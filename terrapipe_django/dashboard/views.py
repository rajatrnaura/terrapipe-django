# dashboard/views.py
from django.http import JsonResponse
from django.views.decorators.http import require_POST, require_GET
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
import jwt
import datetime
import uuid
import json
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from dashboard.models import User  # Correct import
from .models import UserFields , Application

from django.http import JsonResponse, HttpResponse
import requests
from django.conf import settings

from dotenv import load_dotenv
import os
from django.shortcuts import render

from django.http import JsonResponse
from dashboard.models import User, UserFields  # Replace 'yourapp' with the correct app name
from django.db.models import F

import re

load_dotenv()


def token_required(view_func):
    def wrapper(request, *args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse(
                {"message": "Missing or invalid authorization header"},
                status=401
            )
        token = auth_header.split(' ')[1]
        try:
            decoded = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=['HS256'])
            request.decoded_user = decoded
        except jwt.InvalidTokenError:
            return JsonResponse(
                {"message": "Invalid token"},
                status=401
            )
        return view_func(request, *args, **kwargs)
    return wrapper

@require_POST
@csrf_exempt
def login(request):
    
    # curl -X POST "http://127.0.0.1:8000/api/login/" -H "Content-Type: application/json" -d '{"email": "demo@gmail.com", "password": "Admin@1234"}'
    try:
        # Parse the request body as JSON
        data = json.loads(request.body)
        email = data.get('email')
        password = data.get('password')

        # Validate input
        if not email or not password:
            return JsonResponse(
                {"message": "Email and password are required."},
                status=400
            )

        # Validate email format
        try:
            validate_email(email)
        except ValidationError:
            return JsonResponse(
                {"message": "Invalid email format."},
                status=400
            )

        # Check if a user with this email already exists
        user = User.objects.filter(email=email).first()
        if user:
            # User exists, use their user_registry_id
            user_registry_id = str(user.user_registry_id)
        else:
            # User doesn't exist, create a new user
            user_registry_id = str(uuid.uuid4())  # Generate a new user_registry_id
            user = User(
                user_registry_id=user_registry_id,
                email=email,
                phone_num=None,
                coordinates=None,
                is_admin=False
            )
            user.save()

        # Generate JWT token
        payload = {
            'sub': user_registry_id,
            'uuid': user_registry_id,  # For compatibility with Flask API
            'iat': datetime.datetime.utcnow(),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expires in 1 hour
        }
        token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm='HS256')
        request.session['access_token'] = token
        request.session['user_registry_id'] = user_registry_id 
        # Return the token in the response
        return JsonResponse(
            {
                "message": "Login successful",
                "access_token": token
            },
            status=200
        )

    except json.JSONDecodeError:
        return JsonResponse(
            {"message": "Invalid JSON in request body"},
            status=400
        )
    except Exception as e:
        return JsonResponse(
            {
                "message": "Login error",
                "error": str(e)
            },
            status=400
        )


@require_POST
@csrf_exempt
def logout_view(request):
    request.session.flush()  # clears all session data
    return JsonResponse({"message": "Logged out successfully"})


@require_GET
def get_user_geoids_with_details(request):
    """
    Fetch all geo_ids and field names for a given user_id (registry UUID).
    """
    user_registry_id_str = request.GET.get('user_id')
    if not user_registry_id_str:
        return JsonResponse({"message": "Missing user_id"}, status=400)

    try:
        user_registry_id = uuid.UUID(user_registry_id_str)
    except ValueError:
        return JsonResponse({"message": "Invalid UUID format"}, status=400)

    # user = User.objects.only("id").filter(user_registry_id=user_registry_id).first()
    user = User.objects.only("id").filter(user_registry_id=user_registry_id).first()

    if not user:
        return JsonResponse({"message": "User not found"}, status=404)

    user_fields = UserFields.objects.select_related('field').filter(user_id=user.id).values_list('field__geo_id', flat=True)

    asset_url_base = os.getenv("ASSET_REGISTRY_BASE_URL", "https://api-ar.agstack.org/")
    fields_info = []

    for geo_id in user_fields:
        try:
            response = requests.get(f"{asset_url_base}fetch-field/{geo_id}")
            response.raise_for_status()
            field_data = response.json()
            fields_info.append({
                "geo_id": geo_id,
                # "field_name": field_data.get("field_name", "Unknown")
            })
        except requests.RequestException as e:
            continue  # Log error if needed

    return JsonResponse({
        "message": "GeoID and field name list retrieved successfully",
        "fields": fields_info
    }, status=200)
        
        
def get_user_geoids(request):
    user_registry_id_str = request.GET.get('user_id')
    if not user_registry_id_str:
        return JsonResponse({"message": "Missing user_id query parameter"}, status=400)

    try:
        user_registry_id = uuid.UUID(user_registry_id_str)
    except ValueError:
        return JsonResponse({"message": "Invalid user_id format"}, status=400)

    user = User.objects.filter(user_registry_id=user_registry_id).only('id').first()

    if not user:
        return JsonResponse({"message": "User not found"}, status=404)

    user_fields = UserFields.objects.select_related('field').filter(user_id=user.id)

    geoid_fieldname_list = [
        {
            "geo_id": uf.field.geo_id,
            "field_name": uf.field_name  # or uf.field.name
        }
        for uf in user_fields if uf.field and uf.field.geo_id
    ]

    return JsonResponse(
        {
            "message": "GeoIDs retrieved successfully",
            "geo_ids": geoid_fieldname_list
        },
        status=200
    )


# @require_GET
# @token_required
# def get_user_geoids(request):
    
# #     curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1ZDE1ZTJkZC1mZWI1LTRmMGMtOTMxNC03NzYwY2Q4NmQ0NzQiLCJ1dWlkIjoiNWQxNWUyZGQtZmViNS00ZjBjLTkzMTQtNzc2MGNkODZkNDc0IiwiaWF0IjoxNzQ5ODMyOTE2LCJleHAiOjE3NDk4MzY1MTZ9.KiWD4mrD1vexg8mtaz-9EatcLcZgz_u_U86wetooD6o" \
# # "http://127.0.0.1:8000/api/get-user-geoids/"
    
#     try:
#         user_registry_id = request.decoded_user.get('sub')
        
#         user = User.objects.filter(user_registry_id=user_registry_id).first()
#         if not user:
#             return JsonResponse(
#                 {"message": "User not found"},
#                 status=404
#             )

#         user_id = user.id
#         # user_id = 'c027cffc-49df-42fb-b02c-2d5c0de37328'
#         field_ids = UserFields.objects.filter(user_id=user_id).values_list('field_id', flat=True)
#         if not field_ids:
#             return JsonResponse(
#                 {
#                     "message": "No fields found for this user",
#                     "geo_ids": []
#                 },
#                 status=200
#             )

#         user_geo_ids = Fields.objects.filter(id__in=field_ids).values_list('geo_id', flat=True)

#         if not user_geo_ids:
#             return JsonResponse(
#                 {
#                     "message": "No GeoIDs found for this user",
#                     "geo_ids": []
#                 },
#                 status=200
#             )

#         return JsonResponse(
#             {
#                 "message": "GeoIDs retrieved successfully",
#                 "geo_ids": list(user_geo_ids)
#             },
#             status=200
#         )

#     except Exception as e:
#         return JsonResponse(
#             {
#                 "message": "Error retrieving GeoIDs",
#                 "error": str(e)
#             },
#             status=400
#         )
        
        
# @require_GET
# def get_user_geoids(request):
#     try:
#         # Get the user_id from query parameters
#         user_id = request.GET.get('user_id')

#         # Check if user_id is provided
#         if not user_id:
#             return JsonResponse(
#                 {"message": "User ID is required"},
#                 status=400
#             )

#         # Fetch field_ids associated with the user from users_fields
#         field_ids = UserFields.objects.filter(user_id=user_id).values_list('field_id', flat=True)

#         if not field_ids:
#             return JsonResponse(
#                 {
#                     "message": "No fields found for this user",
#                     "geo_ids": []
#                 },
#                 status=200
#             )

#         # Fetch geo_ids from the fields table where id matches the field_ids
#         user_geo_ids = Fields.objects.filter(id__in=field_ids).values_list('geo_id', flat=True)

#         if not user_geo_ids:
#             return JsonResponse(
#                 {
#                     "message": "No GeoIDs found for this user",
#                     "geo_ids": []
#                 },
#                 status=200
#             )

#         # Convert QuerySet to list and return
#         return JsonResponse(
#             {
#                 "message": "GeoIDs retrieved successfully",
#                 "geo_ids": list(user_geo_ids)
#             },
#             status=200
#         )

#     except Exception as e:
#         return JsonResponse(
#             {
#                 "message": "Error retrieving GeoIDs",
#                 "error": str(e)
#             },
#             status=400
#         )

# @token_required
# def products(request):
#     products = [
#         {"id": 1, "name": "Product A"},
#         {"id": 2, "name": "Product B"},
#         {"id": 3, "name": "Product C"},
#     ]
#     return JsonResponse({
#         'message': f'Welcome, user {request.decoded_user["sub"]}!',
#         'products': products
#     })

@token_required
def products(request):
    applications = Application.objects.all().values('id', 'root', 'description', 'picture')
    
    data = [
        {
            "id": str(app['id']),
            "root": app['root'],
            "description": app['description'],
            "picture": app['picture']
        }
        for app in applications
    ]
    
    return JsonResponse({
        'message': f'Welcome, user {request.decoded_user["sub"]}!',
        'products': data
    })


def login_page(request):
    return render(request, 'login.html', {
        'token': request.COOKIES.get('access_token')
    })

def products_page(request):
    return render(request, 'products.html', {
        'token': request.COOKIES.get('access_token')
    })



FIELD_BOUNDARIES = {
    "8e5837ead80d421ce0505fad661052109a87aaefc4c992a34b5b34be1c81010d": {
        "type": "Polygon",
        "coordinates": [[[76.7, 30.9], [76.8, 30.9], [76.8, 31.0], [76.7, 31.0], [76.7, 30.9]]]
    },
    "4ab84f94b206cd54f7acb7599c488c4f8cb672c13b9cc07fc26ecabff27f4259": {
        "type": "Polygon",
        "coordinates": [[[76.5, 30.7], [76.6, 30.7], [76.6, 30.8], [76.5, 30.8], [76.5, 30.7]]]
    }
}

def map_view(request):
    return render(request, "map.html")


def get_user_registry_id_from_session(request):
    user_registry_id = request.session.get('user_registry_id')
    if not user_registry_id:
        return None

    return user_registry_id
    
# def get_geoids(request):
#     user_registry_id = get_user_registry_id_from_session(request)
#     print(f"user_registry_id_str : {user_registry_id}")
#     return JsonResponse({"geoids": GEOIDS})

# def get_geoids(request):
#     # user_registry_id = get_user_registry_id_from_session(request)
#     # print(f"user_registry_id_str : {user_registry_id}")
#     token = request.session.get('access_token')
#     print(f"token : {token}")

#     user_registry_id = request.session.get('user_registry_id')

#     print(f"user_registry_id : {user_registry_id}")

#     # You might need to send auth headers or pass the user_registry_id in some way depending on your API's auth method.
#     # Assuming you have a token or some auth header to pass:
#     headers = {
#         "Authorization": f"Bearer {token}" 
#     }

#     try:
#         response = requests.get(
#             "https://api.terrapipe.io/geo-id",
#             headers=headers,
#             timeout=10
#         )
#         response.raise_for_status()

#         data = response.json()
#         return JsonResponse(data, status=200)

#     except requests.exceptions.RequestException as e:
#         return JsonResponse({"error": f"Failed to fetch geo IDs: {str(e)}"}, status=500)
    

# Match 64-character hex strings only (no dashes, lowercase/uppercase)
VALID_GEO_ID_REGEX = re.compile(r'^[a-f0-9]{64}$', re.IGNORECASE)

def get_geoids(request):
    try:
        user_registry_id = request.session.get('user_registry_id')
        if not user_registry_id:
            return JsonResponse({'message': 'User not authenticated'}, status=401)

        try:
            user = User.objects.get(user_registry_id=user_registry_id)
        except User.DoesNotExist:
            return JsonResponse({'message': 'User not found'}, status=404)

        geo_data = (
            UserFields.objects
            .filter(user=user)
            .select_related('field')
            .values_list('field__geo_id', flat=True)
        )

        # Filter and deduplicate
        geo_ids = list({
            geo_id for geo_id in geo_data
            if geo_id and VALID_GEO_ID_REGEX.fullmatch(geo_id)
        })

        if not geo_ids:
            return JsonResponse({'message': 'No valid Geo Ids found for the user.'}, status=404)

        return JsonResponse({
            'message': 'Geo Ids fetched Successfully',
            'geoids': geo_ids
        }, status=200)

    except Exception as e:
        return JsonResponse({
            'message': 'Fetch Geo Id(s) Error :::',
            'error': str(e)
        }, status=400)


def get_field_boundary(request, geoid):
    geometry = FIELD_BOUNDARIES.get(geoid)
    return JsonResponse({"geoid": geoid, "geometry": geometry})
