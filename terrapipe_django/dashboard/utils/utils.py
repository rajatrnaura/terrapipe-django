import json
import hashlib
import jwt
import pyproj
import requests
import shapely
from shapely import ops
from shapely.wkt import loads
from shapely.geometry import mapping
from functools import wraps, partial
import geojson
from django.http import JsonResponse
from django.conf import settings
import os
import geopandas as gpd
from dashboard.models import S2CellToken , GeoIDs , CellsGeoID
import jwt
import requests
from dashboard import config 
from django.http import HttpRequest
# from dashboard.config import SECRET_KEY
from dashboard.config import DevelopmentConfig 


class Utils:

    @staticmethod
    def get_bearer_token(request):
        bearer = request.headers.get('Authorization')
        if bearer and len(bearer.split()) > 1:
            return bearer.split()[1]
        return None

    @staticmethod
    def fetch_token(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            try:
                token = Utils.get_bearer_token(request)
                refresh_token = request.headers.get('X-Refresh-Token')

                if not token and request.COOKIES.get('access_token_cookie') and request.COOKIES.get('refresh_token_cookie'):
                    token = request.COOKIES.get('access_token_cookie')
                    refresh_token = request.COOKIES.get('refresh_token_cookie')

                if not token:
                    return JsonResponse({'message': 'Token is missing !!'}, status=401)

                try:
                    jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
                except:
                    return JsonResponse({'message': 'Token is invalid !!'}, status=401)

                return view_func(request, token, refresh_token, *args, **kwargs)
            except Exception as e:
                return JsonResponse({'message': 'Authentication Error', 'error': str(e)}, status=401)

        return wrapper

    @staticmethod
    def token_required(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            auth_keys = request.headers.get('API-KEYS-AUTHENTICATION')
            if auth_keys:
                if not request.headers.get('API-KEY') or not request.headers.get('CLIENT-SECRET'):
                    return JsonResponse({'message': 'API Key or Client Secret missing!!'}, status=401)
                if Utils.verify_api_secret_keys(request.headers.get('API-KEY'), request.headers.get('CLIENT-SECRET')):
                    return view_func(request, *args, **kwargs)
                else:
                    return JsonResponse({'message': 'Invalid API Key or Client Secret.'}, status=401)

            token = Utils.get_bearer_token(request)
            if not token:
                return JsonResponse({'message': 'Need to Login.'}, status=401)

            try:
                decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
                if not decoded_token.get('is_activated', True):
                    return JsonResponse({'message': 'User account not activated.'}, status=401)
            except:
                return JsonResponse({'message': 'Need to Login.'}, status=401)

            return view_func(request, *args, **kwargs)

        return wrapper

    @staticmethod
    def generate_geo_id(s2_cell_tokens):
        m = hashlib.sha256()
        for s in s2_cell_tokens:
            m.update(s.encode())
        return m.hexdigest()

    @staticmethod
    def is_valid_polygon(field_wkt):
        try:
            poly = shapely.wkt.loads(field_wkt)
            return poly.geom_type == 'Polygon'
        except:
            return False

    @staticmethod
    def get_geo_json(field_wkt):
        geojson_dict = {"type": "Feature"}
        geojson_string = geojson.dumps(mapping(loads(field_wkt)))
        geojson_dict["geometry"] = json.loads(geojson_string)
        return geojson_dict

    @staticmethod
    def get_are_in_acres(wkt):
        geom = loads(wkt)
        geom_area = ops.transform(
            partial(
                pyproj.transform,
                pyproj.Proj(init='EPSG:4326'),
                pyproj.Proj(
                    proj='aea',
                    lat_1=geom.bounds[1],
                    lat_2=geom.bounds[3])
            ),
            geom)

        area_in_sq_km = geom_area.area / 1000000
        area_in_acres = area_in_sq_km * 247.105
        return area_in_acres

    @staticmethod
    def geojson_to_wkt(geojson_feature):
        try:
            from shapely.geometry import shape
            geometry = shape(geojson_feature['geometry'])
            return geometry.wkt
        except Exception as e:
            raise ValueError(f"Failed to convert GeoJSON to WKT: {str(e)}")
        
    # @staticmethod
    # def get_s2_indexes_to_remove(s2_indexes):
    #     """
    #     Fetches the S2 indexes from the given list, which are not required in the JSON response
    #     :param s2_indexes:
    #     :return:
    #     """
    #     valid_s2_indexes_set = set([8, 13, 15, 18, 19, 20])
    #     s2_indexes_set = set(s2_indexes)
    #     if valid_s2_indexes_set & s2_indexes_set:
    #         return list(valid_s2_indexes_set - s2_indexes_set)
    #     else:
    #         return -1
    
    
    @staticmethod
    def get_s2_indexes_to_remove(s2_indexes):
        valid_s2_indexes_set = {8, 13, 15, 18, 19, 20}
        s2_indexes_set = set(s2_indexes)
        return list(valid_s2_indexes_set - s2_indexes_set)
        
    @staticmethod
    def get_country_from_point(p):
        """
        Fetch country name from a given point (shapely.geometry.Point)
        """
        try:
            # Update this path to match the correct location inside your Django project
            static_folder = os.path.join(settings.BASE_DIR, 'static')
            world_shp_file = os.path.join(static_folder, '99bfd9e7-bb42-4728-87b5-07f8c8ac631c2020328-1-1vef4ev.lu5nk.shp')

            wrs_gdf = gpd.read_file(world_shp_file)
            wrs_gdf = wrs_gdf.to_crs(4326)

            return wrs_gdf[wrs_gdf.contains(p)].reset_index(drop=True).CNTRY_NAME.iloc[0]
        except Exception as e:
            return ''
        
    @staticmethod
    def lookup_geo_ids(geo_id_to_lookup):
        """
        Check if the geo id (field boundary) is already registered.
        Returns the fetched Field WKT if available.
        """
        record = GeoIDs.objects.filter(geo_id=geo_id_to_lookup).first()
        if record and record.geo_data:
            try:
                return json.loads(record.geo_data).get('wkt')
            except (json.JSONDecodeError, TypeError):
                return None
        return None

        
    @staticmethod
    def records_s2_cell_tokens(s2_cell_tokens_dict: dict):
        """
        creates database records for the s2 cell tokens
        :param s2_cell_tokens_dict:
        :return:
        """
        # tokens_dict = {}
        tokens_dict_middle_table = {}
        for res_level, s2_cell_tokens in s2_cell_tokens_dict.items():
            records_list_s2_cell_tokens_middle_table = []
            for s2_cell_token in s2_cell_tokens:
                records_list_s2_cell_tokens_middle_table.append(S2CellToken(cell_token=s2_cell_token))
            # tokens_dict is a dictionary with structure e.g. {res_level: s2_cell_token_records_for_the_db}
            tokens_dict_middle_table[res_level] = records_list_s2_cell_tokens_middle_table

        return tokens_dict_middle_table
    
    
    @staticmethod
    def get_bearer_token(request: HttpRequest):
        """
        Extracts bearer token from Authorization header in Django request
        """
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if auth_header.startswith('Bearer '):
            return auth_header[7:]
        return None

    @staticmethod
    def get_domain_from_jwt(request: HttpRequest):
        """
        Get domain from JWT token in Django request
        """
        try:
            token = Utils.get_bearer_token(request)
            if not token:
                return None
            decoded = jwt.decode(token, config.SECRET_KEY, algorithms=["HS256"])
            return decoded.get('domain')
        except Exception as e:
            return None

    @staticmethod
    def get_authority_token_for_domain(domain):
        """
        Fetch the authority token against a domain from User Registry
        """
        try:
            url = f"{config.USER_REGISTRY_BASE_URL}/authority-token/?domain={domain}"
            res = requests.get(url, timeout=2)
            if res.status_code == 200:
                json_res = res.json()
                return json_res.get('Authority Token')
        except Exception as e:
            return None
    
    @staticmethod
    def fetch_domain_from_client_secret(request):
        try:
            client_secret = request.headers.get('CLIENT-SECRET')
            if not client_secret:
                return None

            decoded = jwt.decode(client_secret, DevelopmentConfig, algorithms=["HS256"])
            return decoded.get('sub')  # 'sub' usually stores the domain or subject
        except Exception as e:
            raise e
    
    @staticmethod
    def register_field_boundary(request, geo_id, indices, records_list_s2_cell_tokens_middle_table_dict, field_wkt, country, boundary_type):
        try:
            geo_data = {'wkt': field_wkt}
            authority_token = None

            domain = Utils.get_domain_from_jwt(request)
            if not domain:
                domain = Utils.fetch_domain_from_client_secret(request)
            if domain:
                authority_token = Utils.get_authority_token_for_domain(domain)

            geo_id_record = GeoIDs(
                geo_id=geo_id,
                authority_token=authority_token,
                country=country,
                boundary_type=boundary_type
            )
            geo_id_record.save()

            all_tokens = []

            for res_level, s2_cell_tokens_records in records_list_s2_cell_tokens_middle_table_dict.items():
                geo_data[res_level] = indices[res_level]

                token_strs = [t.cell_token for t in s2_cell_tokens_records]

                existing_qs = S2CellToken.objects.filter(cell_token__in=token_strs)
                existing_map = {obj.cell_token: obj for obj in existing_qs}
                new_tokens = []

                for record in s2_cell_tokens_records:
                    if record.cell_token not in existing_map:
                        new_tokens.append(S2CellToken(cell_token=record.cell_token))  # ✅ Correct model instance


                if new_tokens:
                    S2CellToken.objects.bulk_create(new_tokens)

                all_tokens.extend(existing_qs)
                all_tokens.extend(new_tokens)

            geo_id_record.geo_data = geo_data
            geo_id_record.save()

            if all_tokens:
                CellsGeoID.objects.bulk_create([
                    CellsGeoID(geo_id=geo_id_record, cell_id=token) for token in all_tokens
                ])

            return geo_data

        except Exception as e:
            raise e
        
        
    @staticmethod
    def get_specific_s2_index_geo_data(geo_data, s2_indexes_to_remove):
        """
        Get only specific S2 indexes data in geo_data (json data)
        :param geo_data:
        :param s2_indexes_to_remove:
        :return:
        """
        geo_data = json.loads(geo_data)
        for key in s2_indexes_to_remove:
            del geo_data[str(key)]
        return geo_data
    
    @staticmethod
    def get_geo_json(field_wkt):
        """
        Fetch the Geo JSON for the given field WKT
        :param field_wkt:
        :return:
        """
        geojson_dict = {"type": "Feature"}
        geojson_string = geojson.dumps(mapping(loads(field_wkt)))
        geojson_dict["geometry"] = json.loads(geojson_string)
        return geojson_dict