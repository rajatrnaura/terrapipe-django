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

from dotenv import load_dotenv
import os
from django.shortcuts import render

from django.http import JsonResponse
from dashboard.models import User, UserFields  # Replace 'yourapp' with the correct app name
from django.db.models import F

import re

import stripe
from django.conf import settings
from django.shortcuts import render, redirect
from django.views import View
from .models import ProductPlan, UserSubscription

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
            decoded = jwt.decode(token, settings.TP_SECRET_KEY, algorithms=['HS256'])
            request.decoded_user = decoded
        except jwt.InvalidTokenError:
            return JsonResponse(
                {"message": "Invalid token"},
                status=401
            )
        return view_func(request, *args, **kwargs)
    return wrapper

# @require_POST
# @csrf_exempt
# def login(request):
    
#     # curl -X POST "http://127.0.0.1:8000/api/login/" -H "Content-Type: application/json" -d '{"email": "demo@gmail.com", "password": "Admin@1234"}'
#     try:
#         # Parse the request body as JSON
#         data = json.loads(request.body)
#         email = data.get('email')
#         password = data.get('password')

#         # Validate input
#         if not email or not password:
#             return JsonResponse(
#                 {"message": "Email and password are required."},
#                 status=400
#             )

#         # Validate email format
#         try:
#             validate_email(email)
#         except ValidationError:
#             return JsonResponse(
#                 {"message": "Invalid email format."},
#                 status=400
#             )

#         # Check if a user with this email already exists
#         user = User.objects.filter(email=email).first()
#         if user:
#             # User exists, use their user_registry_id
#             user_registry_id = str(user.user_registry_id)
#         else:
#             # User doesn't exist, create a new user
#             user_registry_id = str(uuid.uuid4())  # Generate a new user_registry_id
#             user = User(
#                 user_registry_id=user_registry_id,
#                 email=email,
#                 phone_num=None,
#                 coordinates=None,
#                 is_admin=False
#             )
#             user.save()

#         # Generate JWT token
#         payload = {
#             'sub': user_registry_id,
#             'uuid': user_registry_id,  # For compatibility with Flask API
#             'iat': datetime.datetime.utcnow(),
#             'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expires in 1 hour
#         }
#         token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm='HS256')
#         request.session['access_token'] = token
#         request.session['user_registry_id'] = user_registry_id 
#         # Return the token in the response
#         return JsonResponse(
#             {
#                 "message": "Login successful",
#                 "access_token": token
#             },
#             status=200
#         )

#     except json.JSONDecodeError:
#         return JsonResponse(
#             {"message": "Invalid JSON in request body"},
#             status=400
#         )
#     except Exception as e:
#         return JsonResponse(
#             {
#                 "message": "Login error",
#                 "error": str(e)
#             },
#             status=400
#         )


@csrf_exempt
@require_POST
def login(request):
    try:
        data = json.loads(request.body)
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return JsonResponse({"message": "Email and password required"}, status=400)

        flask_login_url = "https://api.terrapipe.io/"
        response = requests.post(flask_login_url, json={"email": email, "password": password})

        print(f"response : {response.json()}")
        if response.status_code == 200:
            resp_data = response.json()
            token = resp_data.get("access_token")
            print(f"token : {token}")
            if not token:
                return JsonResponse({"message": "Token not found in response"}, status=500)
            # print(f"key : {settings.TP_SECRET_KEY}")
            try:
                decoded = jwt.decode(token, settings.TP_SECRET_KEY, algorithms=["HS256"])

                user_registry_id = decoded.get("sub")
            except jwt.ExpiredSignatureError:
                return JsonResponse({"message": "Token expired"}, status=401)
            except jwt.InvalidTokenError as e:
                return JsonResponse({"message": "Invalid token", "error": str(e)}, status=401)
            except Exception as e:
                return JsonResponse({"message": "Unexpected error", "error": str(e)}, status=500)

            # Save token and user_registry_id in session
            request.session["access_token"] = token
            request.session["user_registry_id"] = user_registry_id

            print(f"token : {token}")
            print(f'user_registry_id : {user_registry_id}')
            return JsonResponse({
                "message": "Login successful",
                "access_token": token,
                "user_registry_id": user_registry_id
            })

        else:
            return JsonResponse({
                "message": "Login failed",
                "error": response.json().get("message", "Unknown error")
            }, status=response.status_code)

    except Exception as e:
        return JsonResponse({"message": "Login error", "error": str(e)}, status=500)

@require_POST
@csrf_exempt
def logout_view(request):
    request.session.flush()
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
        'message': f'Welcome, user {request.session.get('user_registry_id')}!',
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



# FIELD_BOUNDARIES = {
#     "8e5837ead80d421ce0505fad661052109a87aaefc4c992a34b5b34be1c81010d": {
#         "type": "Polygon",
#         "coordinates": [[[76.7, 30.9], [76.8, 30.9], [76.8, 31.0], [76.7, 31.0], [76.7, 30.9]]]
#     },
#     "4ab84f94b206cd54f7acb7599c488c4f8cb672c13b9cc07fc26ecabff27f4259": {
#         "type": "Polygon",
#         "coordinates": [[[76.5, 30.7], [76.6, 30.7], [76.6, 30.8], [76.5, 30.8], [76.5, 30.7]]]
#     }
# }

def asset_map_view(request):
    return render(request, "asset_map.html")


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

# def get_geoids(request):
#     try:
#         user_registry_id = request.session.get('user_registry_id')
#         if not user_registry_id:
#             return JsonResponse({'message': 'User not authenticated'}, status=401)

#         try:
#             user = User.objects.get(user_registry_id=user_registry_id)
#         except User.DoesNotExist:
#             return JsonResponse({'message': 'User not found'}, status=404)

#         geo_data = (
#             UserFields.objects
#             .filter(user=user)
#             .select_related('field')
#             .values_list('field__geo_id', flat=True)
#         )

#         # Filter and deduplicate
#         geo_ids = list({
#             geo_id for geo_id in geo_data
#             if geo_id and VALID_GEO_ID_REGEX.fullmatch(geo_id)
#         })

#         if not geo_ids:
#             return JsonResponse({'message': 'No valid Geo Ids found for the user.'}, status=404)

#         return JsonResponse({
#             'message': 'Geo Ids fetched Successfully',
#             'geoids': geo_ids
#         }, status=200)

#     except Exception as e:
#         return JsonResponse({
#             'message': 'Fetch Geo Id(s) Error :::',
#             'error': str(e)
#         }, status=400)


def get_geoids(request):
    try:
        access_token = request.session.get('access_token')
        if not access_token:
            return JsonResponse({'message': 'User not authenticated'}, status=401)

        flask_url = "https://api.terrapipe.io/geo-id"
        headers = {
            "Authorization": f"Bearer {access_token}"
        }

        response = requests.get(flask_url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            geo_ids_raw = data.get("geo_ids", [])

            geo_ids = list({
                geo_id for geo_id, _, _ in geo_ids_raw
                if geo_id and VALID_GEO_ID_REGEX.fullmatch(geo_id)
            })

            if not geo_ids:
                return JsonResponse({'message': 'No valid Geo Ids found.'}, status=404)

            return JsonResponse({
                'message': 'Geo Ids fetched successfully',
                'geoids': geo_ids
            }, status=200)

        else:
            return JsonResponse({
                'message': 'Failed to fetch geo ids from Flask',
                'error': response.json().get("message", "Unknown error")
            }, status=response.status_code)

    except Exception as e:
        return JsonResponse({
            'message': 'Error while fetching geo ids',
            'error': str(e)
        }, status=500)


# def get_field_boundary(request, geoid):
#     geometry = FIELD_BOUNDARIES.get(geoid)
#     return JsonResponse({"geoid": geoid, "geometry": geometry})


# FIELD_BOUNDARIES = {
#     "8e5837ead80d421ce0505fad661052109a87aaefc4c992a34b5b34be1c81010d": {
#         "type": "Polygon",
#         "coordinates": [[[76.7, 30.9], [76.8, 30.9], [76.8, 31.0], [76.7, 31.0], [76.7, 30.9]]]
#     },
#     "4ab84f94b206cd54f7acb7599c488c4f8cb672c13b9cc07fc26ecabff27f4259": {
#         "type": "Polygon",
#         "coordinates": [[[76.5, 30.7], [76.6, 30.7], [76.6, 30.8], [76.5, 30.8], [76.5, 30.7]]]
#     }
# }

def get_field_boundary(request, geoid):
    try:
        access_token = request.session.get("access_token")
        if not access_token:
            return JsonResponse({"message": "User not authenticated"}, status=401)

        flask_url = f"https://api.terrapipe.io/fetch-field/{geoid}"
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(flask_url, headers=headers, timeout=10)

        if response.status_code != 200:
            return JsonResponse({
                "message": "Failed to fetch field data",
                "error": response.json().get("message", "Unknown error")
            }, status=response.status_code)

        data = response.json()

        json_resp = data.get("JSON Response", {})
        geojson = json_resp.get("Geo JSON", {})
        geometry = geojson.get("geometry", {})
        coordinates = geometry.get("coordinates")

        covering_scopes_raw = data.get("covering_scopes")
        if isinstance(covering_scopes_raw, str):
            try:
                covering_scopes = json.loads(covering_scopes_raw)
            except json.JSONDecodeError:
                covering_scopes = {}
        else:
            covering_scopes = covering_scopes_raw or {}

        return JsonResponse({
            "geoid": geoid,
            "coordinates": coordinates,
            "geometry_type": geometry.get("type"),
            "field_name": data.get("field_name"),
            "registered": data.get("registered"),
            "user_field_id": data.get("user_field_id"),
            "covering_scopes": covering_scopes,
            "all_scopes_paid": data.get("all_scopes_paid"),
            "raw_geojson": geojson,
            "raw_response": json_resp
        }, status=200)

    except Exception as e:
        return JsonResponse({
            "message": "Error while fetching field boundary",
            "error": str(e)
        }, status=500)
    
@csrf_exempt
def delete_field(request, field_id):
    access_token = request.session.get("access_token")
    if not access_token:
        return JsonResponse({"success": False, "message": "User not authenticated"}, status=401)

    flask_api_url = f"https://api.terrapipe.io/delete-field/{field_id}"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }

    try:
        response = requests.delete(flask_api_url, headers=headers)

        try:
            data = response.json()
            print(f"data : {data}")
        except ValueError:
            return JsonResponse({"success": False, "message": "Flask response was not JSON"}, status=500)

        if response.status_code == 200:
            return JsonResponse({"success": True, "message": data.get("message", "Field deleted")})
        else:
            return JsonResponse({"success": False, "message": data.get("message", "Failed to delete")}, status=response.status_code)

    except requests.RequestException as e:
        return JsonResponse({"success": False, "message": f"Error calling Flask API: {e}"}, status=500)
    

def scope_map(request):
    return render(request , 'scope_map.html')


# def get_user_scope(request):
#     # Dynamic logic here
#     return JsonResponse({
#         "offer": {"name": "Basic", "scopes_limit": "Limits.MANY"},
#         "scopes": ["10SGF", "43RFQ", "55HCV", "17TNG"]
#     })

def get_user_scope(request):
    try:
        access_token = request.session.get('access_token')
        if not access_token:
            return JsonResponse({'message': 'User not authenticated'}, status=401)

        flask_url = "https://api.terrapipe.io/get_user_scope"
        headers = {
            "Authorization": f"Bearer {access_token}"
        }

        response = requests.get(flask_url, headers=headers, timeout=10)
        if response.status_code == 200:
            return JsonResponse(response.json(), status=200)
        else:
            return JsonResponse({
                'message': 'Failed to fetch user scope',
                'error': response.json().get("message", "Unknown error")
            }, status=response.status_code)

    except Exception as e:
        return JsonResponse({
            'message': 'Error while fetching user scope',
            'error': str(e)
        }, status=500)

# def get_coordinates(request, scope):
#     # Dynamic logic here (replace with actual data source, e.g., database)
#     # For now, using a hardcoded response based on the scope
#     coordinates_data = {
#         "55HCV": {
#             "geometry": {
#                 "coordinates": [
#                     [
#                         [144.7776187766, -36.1237354739],
#                         [145.9974355717, -36.1401611357],
#                         [145.9845293538, -37.1298524425],
#                         [144.7490329004, -37.1128273042],
#                         [144.7776187766, -36.1237354739]
#                     ]
#                 ],
#                 "type": "Polygon"
#             },
#             "scope": "55HCV"
#         },
#         "43RFQ": {
#             "geometry": {
#                 "coordinates": [
#                     [
#                         [37.7749, -122.4194],  # Example coordinates for San Francisco
#                         [37.7849, -122.4094],
#                         [37.7749, -122.3994],
#                         [37.7649, -122.4094],
#                         [37.7749, -122.4194]
#                     ]
#                 ],
#                 "type": "Polygon"
#             },
#             "scope": "43RFQ"
#         },
#     }

#     if scope in coordinates_data:
#         return JsonResponse(coordinates_data[scope])
#     else:
#         return JsonResponse({"error": "Scope not found"}, status=404)


@csrf_exempt
def get_coordinates(request, scope):
    try:
        access_token = request.session.get('access_token')
        if not access_token:
            return JsonResponse({'message': 'User not authenticated'}, status=401)

        flask_url = "https://api.terrapipe.io/get-coordinates"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        payload = {
            "scope": scope
        }

        response = requests.post(flask_url, headers=headers, json=payload, timeout=10)
        if response.status_code == 200:
            print(f"response : {response.json()}")
            return JsonResponse(response.json(), status=200)
        else:
            return JsonResponse({
                'message': 'Failed to fetch coordinates',
                'error': response.json().get("message", "Unknown error")
            }, status=response.status_code)

    except Exception as e:
        return JsonResponse({
            'message': 'Error while fetching coordinates',
            'error': str(e)
        }, status=500)
    
@csrf_exempt
def get_scopes_bb(request):
    try:
        access_token = request.session.get('access_token')
        if not access_token:
            return JsonResponse({'message': 'User not authenticated'}, status=401)

        if request.method != 'POST':
            return JsonResponse({'message': 'Method not allowed'}, status=405)

        try:
            data = json.loads(request.body)
            minx = data.get('minx')
            miny = data.get('miny')
            maxx = data.get('maxx')
            maxy = data.get('maxy')
            if not all([minx, miny, maxx, maxy]):
                return JsonResponse({'message': 'One or more parameters missing'}, status=400)
        except json.JSONDecodeError:
            return JsonResponse({'message': 'Invalid JSON data'}, status=400)

        flask_url = "https://api.terrapipe.io/getScopesBB"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        payload = {
            "minx": minx,
            "miny": miny,
            "maxx": maxx,
            "maxy": maxy
        }

        response = requests.post(flask_url, headers=headers, json=payload, timeout=10)
        if response.status_code == 200:
            return JsonResponse(response.json(), status=200)
        else:
            return JsonResponse({
                'message': 'Failed to fetch scopes',
                'error': response.json().get("error", "Unknown error")
            }, status=response.status_code)

    except Exception as e:
        return JsonResponse({
            'message': 'Error while fetching scopes',
            'error': str(e)
        }, status=500)
    

@csrf_exempt
def request_activation(request):
    try:
        access_token = request.session.get('access_token')
        if not access_token:
            return JsonResponse({'message': 'User not authenticated'}, status=401)

        if request.method != 'POST':
            return JsonResponse({'message': 'Method not allowed'}, status=405)

        try:
            data = json.loads(request.body)
            scope_names = data.get('scope')
            coordinates = data.get('coordinates')
            if not scope_names:
                return JsonResponse({'message': 'Parameter missing'}, status=400)

            if isinstance(scope_names, str):
                scope_names = [scope_names]
        except json.JSONDecodeError:
            return JsonResponse({'message': 'Invalid JSON data'}, status=400)

        flask_url = "https://api.terrapipe.io/request-activation"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        payload = {
            "scope": scope_names,
            "coordinates": coordinates
        }

        response = requests.post(flask_url, headers=headers, json=payload, timeout=10)
        print(f"request activation : {response.json()}")
        if response.status_code == 200:
            return JsonResponse(response.json(), status=200)
        else:
            return JsonResponse({
                'message': 'Failed to request activation',
                'error': response.json().get("error", "Unknown error")
            }, status=response.status_code)

    except Exception as e:
        return JsonResponse({
            'message': 'Error while requesting activation',
            'error': str(e)
        }, status=500)

@csrf_exempt
def remove_scope(request):
    try:
        access_token = request.session.get('access_token')
        if not access_token:
            return JsonResponse({'message': 'User not authenticated'}, status=401)

        if request.method != 'POST':
            return JsonResponse({'message': 'Method not allowed'}, status=405)

        try:
            data = json.loads(request.body)
            scope_name = data.get('scope_name')
            if not scope_name:
                return JsonResponse({'message': 'Please provide a scope name'}, status=400)
        except json.JSONDecodeError:
            return JsonResponse({'message': 'Invalid JSON data'}, status=400)

        flask_url = "https://api.terrapipe.io/remove_scope"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        payload = {
            "scope_name": scope_name
        }

        response = requests.post(flask_url, headers=headers, json=payload, timeout=10)
        if response.status_code == 200:
            return JsonResponse(response.json(), status=200)
        else:
            return JsonResponse({
                'message': 'Failed to remove scope',
                'error': response.json().get("error", "Unknown error")
            }, status=response.status_code)

    except Exception as e:
        return JsonResponse({
            'message': 'Error while removing scope',
            'error': str(e)
        }, status=500)

@csrf_exempt
def add_user_scope(request):
    try:
        access_token = request.session.get('access_token')
        if not access_token:
            return JsonResponse({'message': 'User not authenticated'}, status=401)

        if request.method != 'POST':
            return JsonResponse({'message': 'Method not allowed'}, status=405)

        try:
            data = json.loads(request.body)
            scope_name = data.get('scope_name')
            coordinates = data.get('coordinates')
            if not scope_name:
                return JsonResponse({'message': 'Please provide a scope name'}, status=400)
        except json.JSONDecodeError:
            return JsonResponse({'message': 'Invalid JSON data'}, status=400)

        flask_url = "https://api.terrapipe.io/add_user_scope"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        payload = {
            "scope_name": scope_name,
            "coordinates": coordinates
        }

        response = requests.post(flask_url, headers=headers, json=payload, timeout=10)
        if response.status_code == 200:
            return JsonResponse(response.json(), status=200)
        else:
            return JsonResponse({
                'message': 'Failed to add scope',
                'error': response.json().get("error", "Unknown error")
            }, status=response.status_code)

    except Exception as e:
        return JsonResponse({
            'message': 'Error while adding scope',
            'error': str(e)
        }, status=500)


@csrf_exempt
def fetch_field_bb(request):
    try:
        access_token = request.session.get('access_token')
        if not access_token:
            return JsonResponse({'message': 'User not authenticated'}, status=401)

        if request.method != 'POST':
            return JsonResponse({'message': 'Method not allowed'}, status=405)

        try:
            data = json.loads(request.body)
            minx = data.get('minx')
            miny = data.get('miny')
            maxx = data.get('maxx')
            maxy = data.get('maxy')
            if not all([minx, miny, maxx, maxy]):
                return JsonResponse({'message': 'One or more parameters missing'}, status=400)
        except json.JSONDecodeError:
            return JsonResponse({'message': 'Invalid JSON data'}, status=400)

        flask_url = "https://api.terrapipe.io/fetch-field-bb"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        payload = {
            "minx": minx,
            "miny": miny,
            "maxx": maxx,
            "maxy": maxy
        }

        response = requests.post(flask_url, headers=headers, json=payload, timeout=10)
        if response.status_code == 200:
            return JsonResponse(response.json(), status=200)
        else:
            return JsonResponse({
                'message': 'Failed to fetch fields',
                'error': response.json().get("error", "Unknown error")
            }, status=response.status_code)

    except Exception as e:
        return JsonResponse({
            'message': 'Error while fetching fields',
            'error': str(e)
        }, status=500)

def forgot_password_page(request):
    return render(request , 'forgot_password.html')

@csrf_exempt
def forgot_password(request):
    try:
        if request.method != 'POST':
            return JsonResponse({'message': 'Method not allowed'}, status=405)

        email = request.POST.get('email')
        if not email:
            return JsonResponse({'message': 'Email is required'}, status=400)

        flask_url = "https://api.terrapipe.io/forgot-password"

        headers = {
            "Content-Type": "application/json"
        }

        payload = {
            "email": email
        }

        response = requests.post(flask_url, headers=headers, json=payload, timeout=10)
        
        if response.status_code == 200:
            return JsonResponse(response.json(), status=200)
        else:
            return JsonResponse({
                'message': 'Forgot Password Failed',
                'error': response.json().get("error", "Unknown error")
            }, status=response.status_code)

    except Exception as e:
        return JsonResponse({
            'message': 'Forgot Password Error',
            'error': str(e)
        }, status=500)

def signup_page(request):
    return render(request , 'signup.html')

@csrf_exempt
def signup(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)

            payload = {
                "firstName": data.get("firstName"),
                "lastName": data.get("lastName"),
                "companyName": data.get("companyName"),
                "email": data.get("email"),
                "phone_number": data.get("phone_number"),
                "password": data.get("password"),
                "confirm_password": data.get("confirm_password"),
                "coords": data.get("coords")
            }

            flask_url = "https://api.terrapipe.io/signup"
            headers = {"Content-Type": "application/json"}

            response = requests.post(flask_url, headers=headers, json=payload, timeout=10)
            api_response = response.json()

            print(f"res : {api_response}")
            print(f"status: {response.status_code}")

            return JsonResponse(api_response, status=response.status_code)

        except Exception as e:
            return JsonResponse({
                "message": "Signup error",
                "error": str(e)
            }, status=500)

    return JsonResponse({"message": "Method not allowed"}, status=405)


stripe.api_key = settings.STRIPE_SECRET_KEY



def pricing_page(request):
    user_id = request.session.get('user_registry_id')
    plans = ProductPlan.objects.all().order_by('price')
    user_subscription = UserSubscription.objects.filter(user_id=user_id, active=True).first()
    return render(request, 'pricing.html', {
        'plans': plans,
        'user_subscription': user_subscription
    })


# class CreateCheckoutSessionView(View):
#     def post(self, request, *args, **kwargs):
#         user_id = request.session.get('user_registry_id')
#         plan_id = request.POST.get('plan_id')
#         plan = ProductPlan.objects.get(id=plan_id)
#         if user_id:
#             try:
#                 user = User.objects.get(user_registry_id=user_id)
#                 user_email = user.email
#             except User.DoesNotExist:
#                 user_email = None  # Or handle however you want
#         else:
#             user_email = None  # No user_registry_id in session

#         # Free plan: Assign directly
#         if plan.name == 'free':
#             subscription, created = UserSubscription.objects.get_or_create(user_id=user_id)
#             subscription.set_plan(plan)
#             return redirect('pricing_page')

#         # Paid plans: Go to Stripe
#         price_id_map = {
#             'plus': '10',  # Replace with real Stripe price IDs
#             'pro': '30',
#         }
#         price_id = float(price_id_map.get(plan.name))
#         print("plan id ", plan.id)
#         print("user email =====", user_email)
#         print("price id ======", price_id)
#         checkout_session = stripe.checkout.Session.create(
#             line_items=[
#                 {
#                     'price_data' : {
#                         'currency' : 'usd',
#                         'unit_amount' : int(price_id * 100),
#                         'product_data' : {
#                             'name' : plan.name
#                         }
#                     },
#                     'quantity' : 1
                    
#                 }
#             ],
#             mode='payment',
#             success_url=f'http://127.0.0.1:8000/api/success/?plan_id={plan.id}',
#             cancel_url='http://127.0.0.1:8000/api/cancel/',
#             customer_email=user_email,
#         )

#         return redirect(checkout_session.url)

class CreateCheckoutSessionView(View):
    def post(self, request, *args, **kwargs):
        user_id = request.session.get('user_registry_id')
        plan_id = request.POST.get('plan_id')
        plan = ProductPlan.objects.get(id=plan_id)

        if user_id:
            try:
                user = User.objects.get(user_registry_id=user_id)
                user_email = user.email
            except User.DoesNotExist:
                user_email = None
        else:
            user_email = None

        # Free plan: Assign directly
        if plan.name == 'free':
            subscription, _ = UserSubscription.objects.get_or_create(user_id=user_id)
            subscription.set_plan(plan)
            return redirect('pricing_page')

        # Get price from ProductPlan model
        price_amount = float(plan.price)  

        checkout_session = stripe.checkout.Session.create(
            line_items=[
                {
                    'price_data': {
                        'currency': 'usd',
                        'unit_amount': int(price_amount * 100),  # Convert to cents
                        'product_data': {
                            'name': plan.name
                        }
                    },
                    'quantity': 1
                }
            ],
            mode='payment',
            success_url=f'http://127.0.0.1:8000/api/success/?session_id={{CHECKOUT_SESSION_ID}}&plan_id={plan.id}',
            cancel_url='http://127.0.0.1:8000/api/cancel/',
            customer_email=user_email,
        )

        # Reuse or create subscription
        subscription = UserSubscription.objects.filter(user_id=user_id).first()
        if subscription:
            subscription.plan = plan
            subscription.stripe_payment_id = checkout_session.id
            subscription.active = False
            subscription.save()
        else:
            subscription = UserSubscription.objects.create(
                user_id=user_id,
                plan=plan,
                stripe_payment_id=checkout_session.id,
                active=False,
            )

        return redirect(checkout_session.url)


# def payment_success(request):
#     plan_id = request.GET.get('plan_id')
#     plan = ProductPlan.objects.get(id=plan_id)
#     user_id = request.session.get('user_registry_id')

#     if not user_id:
#         return redirect('login_page')

#     # Fetch the current active subscription for this user
#     subscription = UserSubscription.objects.filter(user_id=user_id, active=True).first()

#     if subscription:
#         # Update the existing subscription plan
#         subscription.set_plan(plan)
#     else:
#         # Create a new subscription (optional)
#         subscription = UserSubscription.objects.create(user_id=user_id, plan=plan)
#         subscription.set_plan(plan)

#     return render(request, 'payment_success.html', {'plan': plan})

def payment_success(request):
    session_id = request.GET.get('session_id')
    plan_id = request.GET.get('plan_id')
    user_id = request.session.get('user_registry_id')

    if not user_id:
        return redirect('login_page')

    try:
        plan = ProductPlan.objects.get(id=plan_id)
    except ProductPlan.DoesNotExist:
        return redirect('pricing_page')

    # Find the subscription with the stripe session id
    subscription = UserSubscription.objects.filter(
        user_id=user_id, stripe_payment_id=session_id
    ).first()

    if subscription:
        subscription.set_plan(plan)
    else:
        subscription = UserSubscription.objects.create(
            user_id=user_id, plan=plan, stripe_payment_id=session_id
        )
        subscription.set_plan(plan)

    return render(request, 'payment_success.html', {'plan': plan})


def payment_cancel(request):
    return render(request, 'cancel.html')