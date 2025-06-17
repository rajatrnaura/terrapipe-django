from django.contrib import admin
from .models import User , UserFields , Fields , Application, UserApplicationAssociation

# Register your models here.

# admin.site.register(User)
admin.site.register(UserFields)
admin.site.register(Fields)

@admin.register(Application)
class ApplicationAdmin(admin.ModelAdmin):
    list_display = ['root', 'description']  # Optional

    def get_queryset(self, request):
        qs = super().get_queryset(request)

        if request.user.is_superuser:
            return qs

        # Restrict non-superusers to only associated apps
        allowed_app_ids = UserApplicationAssociation.objects.filter(
            user=request.user
        ).values_list('application_id', flat=True)

        return qs.filter(id__in=allowed_app_ids)