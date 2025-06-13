from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.hashers import check_password
from .models import User, RegistryUser, ProductOffer, Limits
from django.utils import timezone
from django.contrib.auth import user_logged_in

class UserRegistryBackend(BaseBackend):
    def authenticate(self, request, email_or_device_id=None, password=None):
        try:
            print(f"Authenticating email_or_device_id: {email_or_device_id}, user_logged_in receivers: {len(user_logged_in.receivers)}")
            if email_or_device_id and '@' not in email_or_device_id:
                user = RegistryUser.objects.using('user_registry').filter(device_id=email_or_device_id).first()
                if user:
                    print(f"Authenticated user by device_id: {email_or_device_id}")
                    return self._get_or_create_local_user(user)
            else:
                user = RegistryUser.objects.using('user_registry').filter(email=email_or_device_id).first()
                if user:
                    print(f"Found user with email: {email_or_device_id}, stored hash: {user.password}")
                    if password is None:
                        print(f"No password provided for user: {email_or_device_id}")
                        return None
                    password_match = check_password(password, user.password)
                    print(f"Password check for user: {email_or_device_id}, match: {password_match}")
                    if password_match:
                        print(f"Password matched for user: {email_or_device_id} (pbkdf2:sha256)")
                        return self._get_or_create_local_user(user)
                    else:
                        print(f"Password mismatch for user: {email_or_device_id} (pbkdf2:sha256)")
                else:
                    print(f"No user found with email: {email_or_device_id}")
            return None
        except Exception as e:
            print(f"Authentication error: {str(e)}")
            return None

    def _get_or_create_local_user(self, registry_user):
        local_user = User.objects.filter(user_registry_id=registry_user.id).first()
        if not local_user:
            basic_offer = ProductOffer.objects.filter(name='Basic').first()
            basic_offer_id = basic_offer.id if basic_offer else None
            print(f"Creating local user with product_offer_id: {basic_offer_id}")
            local_user = User.objects.create(
                user_registry_id=registry_user.id,
                email=registry_user.email,
                phone_num=registry_user.phone_num,
                coordinates=registry_user.lat_lng,
                product_offer_id=basic_offer_id,
                created_at=timezone.now(),
                is_admin=False
            )
            print(f"Created local user for registry user: {registry_user.id}")
        return local_user

    def get_user(self, user_id):
        try:
            user = User.objects.get(user_registry_id=user_id)
            print(f"Retrieved user: {user_id}")
            return user
        except User.DoesNotExist:
            print(f"User not found: {user_id}")
            return None