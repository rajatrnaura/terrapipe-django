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
from dashboard.utils.utils import Utils
from s2_service import S2Service
from django.http import JsonResponse
from django.conf import settings
from django.db import connections
from dotenv import load_dotenv
import os
from shapely.geometry import Point
from django.http import JsonResponse, HttpResponseBadRequest
from django.shortcuts import render
import requests
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
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
            decoded = jwt.decode(token, settings.TP_SECRET_KEY, algorithms=['HS256'])
            request.decoded_user = decoded
        except jwt.InvalidTokenError:
            return JsonResponse(
                {"message": "Invalid token"},
                status=401
            )
        return view_func(request, *args, **kwargs)
    return wrapper

 
 
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
 
        # print(f"response : {response.json()}")
        if response.status_code == 200:
            resp_data = response.json()
            token = resp_data.get("access_token")
            # print(f"token : {token}")
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
 
            # print(f"token : {token}")
            # print(f'user_registry_id : {user_registry_id}')
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
        'message': f'Welcome, user {request.session.get("user_registry_id")}!',
        'products': data
    })

def asset_map_view(request):
    return render(request, "asset_map.html")

def get_user_registry_id_from_session(request):
    user_registry_id = request.session.get('user_registry_id')
    if not user_registry_id:
        return None

    return user_registry_id

VALID_GEO_ID_REGEX = re.compile(r'^[a-f0-9]{64}$', re.IGNORECASE)
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
            # print(f"data : {data}")
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
            # print(f"response : {response.json()}")
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
        # print(f"request activation : {response.json()}")
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

            # print(f"res : {api_response}")
            # print(f"status: {response.status_code}")

            return JsonResponse(api_response, status=response.status_code)

        except Exception as e:
            return JsonResponse({
                "message": "Signup error",
                "error": str(e)
            }, status=500)

    return JsonResponse({"message": "Method not allowed"}, status=405)


def login_page(request):
    return render(request, 'login.html', {
        'token': request.COOKIES.get('access_token')
    })


@require_POST
@csrf_exempt
def logout_view(request):
    request.session.flush()
    return JsonResponse({"message": "Logged out successfully"})

    
def products_page(request):
    return render(request, 'products.html', {
        'token': request.COOKIES.get('access_token')
    })

 
@require_GET
def get_user_geoids_with_details(request):
    user_registry_id_str = request.GET.get("user_id")
    product_id_str = request.GET.get("product_id")

    if not user_registry_id_str:
        return JsonResponse({"message": "Missing user_id"}, status=400)

    try:
        user_registry_id = str(uuid.UUID(user_registry_id_str))
    except ValueError:
        return JsonResponse({"message": "Invalid UUID format for user_id"}, status=400)

    # Check if user exists locally
    user = User.objects.only("id").filter(user_registry_id=user_registry_id).first()
    if not user:
        return JsonResponse({"message": "User not found"}, status=404)

    # Query the remote Node1 DB
    with connections['node1_db'].cursor() as cursor:
        if product_id_str:
            try:
                product_id = str(uuid.UUID(product_id_str))
            except ValueError:
                return JsonResponse({"message": "Invalid UUID format for product_id"}, status=400)

            cursor.execute("""
                SELECT DISTINCT product_id
                FROM subscriptions
                WHERE user_id = %s AND product_id = %s AND subscription_status = 'active'
            """, [user_registry_id, product_id])
        else:
            cursor.execute("""
                SELECT DISTINCT product_id
                FROM subscriptions
                WHERE user_id = %s AND subscription_status = 'active'
            """, [user_registry_id])

        rows = cursor.fetchall()
        product_ids = [r[0] for r in rows]

    if not product_ids:
        return JsonResponse({"message": "No active subscription(s) found for this user"}, status=404)

    # Fetch geo_ids locally
    user_fields = UserFields.objects.select_related('field').filter(user_id=user.id)
    user_geo_ids = list(user_fields.values_list("field__geo_id", flat=True))

    asset_url_base = os.getenv("ASSET_REGISTRY_BASE_URL", "https://api-ar.agstack.org/")
    response_data = {}

    for pid in product_ids:
        response_data[pid] = {
            "geo_ids": user_geo_ids
        }

    return JsonResponse({
        "message": "GeoID list retrieved successfully",
        "fields": response_data
    }, status=200)
    

# @csrf_exempt
# def register_field_boundary(request):
#     if request.method != 'POST':
#         return HttpResponseBadRequest("Only POST method is allowed.")

#     data = json.loads(request.body.decode('utf-8'))
#     field_wkt = data.get('wkt')
#     threshold = data.get('threshold') or 95
#     resolution_level = 20
#     boundary_type = "manual"

#     if request.headers.get('AUTOMATED-FIELD'):
#         if int(request.headers.get('AUTOMATED-FIELD')) == 1:
#             boundary_type = "automated"

#     field_boundary_geo_json = Utils.get_geo_json(field_wkt)
#     lat = field_boundary_geo_json['geometry']['coordinates'][0][0][1]
#     lng = field_boundary_geo_json['geometry']['coordinates'][0][0][0]
#     p = Point([lng, lat])
#     country = Utils.get_country_from_point(p)
#     # area_acres = Utils.get_are_in_acres(field_wkt)

#     # if area_acres > 1000:
#     #     return JsonResponse({
#     #         "message": "Cannot register a field with Area greater than 1000 acres",
#     #         "Field area (acres)": area_acres
#     #     })

#     s2_index = data.get('s2_index')
#     s2_indexes_to_remove = -1
#     if s2_index:
#         s2_index_to_fetch = [int(i) for i in s2_index.split(',')]
#         s2_indexes_to_remove = Utils.get_s2_indexes_to_remove(s2_index_to_fetch)
#     indices = {
#         8: S2Service.wkt_to_cell_tokens(field_wkt, 8),
#         13: S2Service.wkt_to_cell_tokens(field_wkt, 13),
#         15: S2Service.wkt_to_cell_tokens(field_wkt, 15),
#         18: S2Service.wkt_to_cell_tokens(field_wkt, 18),
#         19: S2Service.wkt_to_cell_tokens(field_wkt, 19),
#         20: S2Service.wkt_to_cell_tokens(field_wkt, 20),
#     }

#     middle_table_records = Utils.records_s2_cell_tokens(indices)
#     geo_id = Utils.generate_geo_id(indices[13])
#     geo_id_l20 = Utils.generate_geo_id(indices[20])

#     existing_geo_wkt = Utils.lookup_geo_ids(geo_id)
#     if not existing_geo_wkt:
#         geo_data = Utils.register_field_boundary(request, geo_id, indices, middle_table_records, field_wkt, country, boundary_type)
#         s2_cell_tokens = indices[20]  # Default to level 20 tokens
#         if s2_index and s2_indexes_to_remove != -1:
#             s2_cell_tokens = Utils.get_specific_s2_index_geo_data(geo_data, s2_indexes_to_remove) or indices[20]
#         return JsonResponse({
#             "message": "Field Boundary registered successfully.",
#             "Geo Id": geo_id,
#             "S2 Cell Tokens": s2_cell_tokens,
#             "Geo JSON": field_boundary_geo_json
#         })

#     s2_tokens_l20 = indices[20]
#     matched_geo_ids = Utils.fetch_geo_ids_for_cell_tokens(s2_tokens_l20, "")
#     match_percent = Utils.check_percentage_match(matched_geo_ids, s2_tokens_l20, resolution_level, threshold)

#     if len(match_percent) > 0:
#         return JsonResponse({
#             "message": "Threshold matched for already registered Field Boundary(ies)",
#             "matched geo ids": match_percent
#         }, status=400)

#     existing_geo_l20_wkt = Utils.lookup_geo_ids(geo_id_l20)
#     if not existing_geo_l20_wkt:
#         geo_data = Utils.register_field_boundary(request, geo_id, indices, middle_table_records, field_wkt, country, boundary_type)
#         s2_cell_tokens = indices[20]  # Default to level 20 tokens
#         if s2_index and s2_indexes_to_remove:
#             s2_cell_tokens = Utils.get_specific_s2_index_geo_data(geo_data, s2_indexes_to_remove) or indices[20]
#         return JsonResponse({
#             "message": "Field Boundary registered successfully.",
#             "Geo Id": geo_id_l20,
#             "S2 Cell Tokens": s2_cell_tokens,
#             "Geo JSON": field_boundary_geo_json
#         })

#     return JsonResponse({
#         "message": "Field Boundary already registered.",
#         "Geo Id": geo_id_l20,
#         "Geo JSON requested": field_boundary_geo_json,
#         "Geo JSON registered": Utils.get_geo_json(existing_geo_l20_wkt)
#     })

@csrf_exempt
def register_field_boundary(request):
    if request.method != 'POST':
        return HttpResponseBadRequest("Only POST method is allowed.")

    try:
        data = json.loads(request.body.decode('utf-8'))

        # Required fields
        field_wkt = data.get('wkt')
        threshold = data.get('threshold', 90)
        s2_index = data.get('s2_index', '8,13')
        resolution_level = data.get('resolution_level', 13)

        if not field_wkt:
            return JsonResponse({"message": "Missing 'wkt' in request body"}, status=400)

        # Get token from session
        token = request.session.get('access_token')

        if not token:
            return JsonResponse({"message": "Missing access token in session"}, status=401)

        # Ensure it starts with Bearer
        if ";" in token:
            token = token.split(";")[0].strip()

        if not token.startswith("Bearer "):
            token = "Bearer " + token

        # Payload
        payload = {
            "wkt": field_wkt,
            "threshold": threshold,
            "s2_index": s2_index,
            "resolution_level": resolution_level
        }

        # Send POST request to AgStack
        agstack_response = requests.post(
            url="https://api-ar.agstack.org/register-field-boundary",
            headers={
                "Content-Type": "application/json",
                "Authorization": token
            },
            json=payload
        )

        if agstack_response.ok:
            return JsonResponse(agstack_response.json(), status=agstack_response.status_code)
        else:
            return JsonResponse({
                "message": "AgStack API returned an error",
                "status_code": agstack_response.status_code,
                "error": agstack_response.text
            }, status=agstack_response.status_code)

    except json.JSONDecodeError:
        return JsonResponse({"message": "Invalid JSON in request body"}, status=400)
    except Exception as e:
        return JsonResponse({"message": "Internal server error", "error": str(e)}, status=500)


    
def map_view(request):
    return render(request, "register_field_map.html")