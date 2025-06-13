from django.contrib.auth import user_logged_in
from django.dispatch import receiver
from .models import User

# Clear all existing user_logged_in receivers
print(f"Clearing user_logged_in receivers: {len(user_logged_in.receivers)} handlers found")
user_logged_in.receivers = []

@receiver(user_logged_in, sender=User)
def skip_last_login_update(sender, request, user, **kwargs):
    print(f"Skipped last_login update for user: {user.user_registry_id}")
    # No-op to prevent last_login update