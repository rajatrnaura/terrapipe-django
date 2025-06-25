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
from .models import UserFields
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
    

@csrf_exempt
def register_field_boundary(request):
    if request.method != 'POST':
        return HttpResponseBadRequest("Only POST method is allowed.")

    data = json.loads(request.body.decode('utf-8'))
    field_wkt = data.get('wkt')
    threshold = data.get('threshold') or 95
    resolution_level = 20
    boundary_type = "manual"

    if request.headers.get('AUTOMATED-FIELD'):
        if int(request.headers.get('AUTOMATED-FIELD')) == 1:
            boundary_type = "automated"

    field_boundary_geo_json = Utils.get_geo_json(field_wkt)
    lat = field_boundary_geo_json['geometry']['coordinates'][0][0][1]
    lng = field_boundary_geo_json['geometry']['coordinates'][0][0][0]
    p = Point([lng, lat])
    country = Utils.get_country_from_point(p)
    # area_acres = Utils.get_are_in_acres(field_wkt)

    # if area_acres > 1000:
    #     return JsonResponse({
    #         "message": "Cannot register a field with Area greater than 1000 acres",
    #         "Field area (acres)": area_acres
    #     })

    s2_index = data.get('s2_index')
    s2_indexes_to_remove = -1
    s2_indexes_to_remove = []
    if s2_index:
        s2_index_to_fetch = [int(i) for i in s2_index.split(',')]
        s2_indexes_to_remove = Utils.get_s2_indexes_to_remove(s2_index_to_fetch)
    indices = {
        8: S2Service.wkt_to_cell_tokens(field_wkt, 8),
        13: S2Service.wkt_to_cell_tokens(field_wkt, 13),
        15: S2Service.wkt_to_cell_tokens(field_wkt, 15),
        18: S2Service.wkt_to_cell_tokens(field_wkt, 18),
        19: S2Service.wkt_to_cell_tokens(field_wkt, 19),
        20: S2Service.wkt_to_cell_tokens(field_wkt, 20),
    }

    middle_table_records = Utils.records_s2_cell_tokens(indices)
    geo_id = Utils.generate_geo_id(indices[13])
    geo_id_l20 = Utils.generate_geo_id(indices[20])

    existing_geo_wkt = Utils.lookup_geo_ids(geo_id)
    if not existing_geo_wkt:
        geo_data = Utils.register_field_boundary(request, geo_id, indices, middle_table_records, field_wkt, country, boundary_type)
        geo_data_to_return = None
        if s2_index and s2_indexes_to_remove != -1:
            geo_data_to_return = Utils.get_specific_s2_index_geo_data(geo_data, s2_indexes_to_remove)
        return JsonResponse({
            "message": "Field Boundary registered successfully.",
            "Geo Id": geo_id,
            "S2 Cell Tokens": geo_data_to_return,
            "Geo JSON": field_boundary_geo_json
        })

    s2_tokens_l20 = indices[20]
    matched_geo_ids = Utils.fetch_geo_ids_for_cell_tokens(s2_tokens_l20, "")
    match_percent = Utils.check_percentage_match(matched_geo_ids, s2_tokens_l20, resolution_level, threshold)

    if len(match_percent) > 0:
        return JsonResponse({
            "message": "Threshold matched for already registered Field Boundary(ies)",
            "matched geo ids": match_percent
        }, status=400)

    existing_geo_l20_wkt = Utils.lookup_geo_ids(geo_id_l20)
    if not existing_geo_l20_wkt:
        geo_data = Utils.register_field_boundary(request, geo_id, indices, middle_table_records, field_wkt, country, boundary_type)
        geo_data_to_return = None
        if s2_index and s2_indexes_to_remove:
            geo_data_to_return = Utils.get_specific_s2_index_geo_data(geo_data, s2_indexes_to_remove)
        return JsonResponse({
            "message": "Field Boundary registered successfully.",
            "Geo Id": geo_id_l20,
            "S2 Cell Tokens": geo_data_to_return,
            "Geo JSON": field_boundary_geo_json
        })

    return JsonResponse({
        "message": "Field Boundary already registered.",
        "Geo Id": geo_id_l20,
        "Geo JSON requested": field_boundary_geo_json,
        "Geo JSON registered": Utils.get_geo_json(existing_geo_l20_wkt)
    })
        



def map_view(request):
    return render(request, "map.html")