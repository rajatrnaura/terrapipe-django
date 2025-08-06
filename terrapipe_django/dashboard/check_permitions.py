from functools import wraps
from django.http import JsonResponse
from .models import UserSubscription, UserScope

def check_scope_limit(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        user_id = kwargs.get('user_id') or request.session.get('user_registry_id')
        
        subscription = UserSubscription.objects.filter(user_id=user_id, active=True).order_by('-start_date').first()
        if not subscription:
            return JsonResponse({'message': 'No active subscription.'}, status=403)

        plan_name = subscription.plan.name.lower()
        active_scope_count = UserScope.objects.filter(user_id=user_id, active=True).count()

        if plan_name == 'free' and active_scope_count >= 1:
            return JsonResponse({'message': 'Free plan allows only 1 scope.'}, status=403)

        if plan_name == 'plus' and active_scope_count >= 1:
            return JsonResponse({'message': 'Plus plan allows only 1 scope.'}, status=403)

        return view_func(request, *args, **kwargs)

    return _wrapped_view
