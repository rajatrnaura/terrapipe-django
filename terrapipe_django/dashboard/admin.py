from django.contrib import admin
from .models import User , UserFields , Fields , Application, UserApplicationAssociation

# Register your models here.

# admin.site.register(User)
admin.site.register(UserFields)
admin.site.register(Fields)

@admin.register(Application)
class ApplicationAdmin(admin.ModelAdmin):
    list_display = ['root', 'description']

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs

        allowed_app_ids = UserApplicationAssociation.objects.filter(
            user=request.user
        ).values_list('application_id', flat=True)

        return qs.filter(id__in=allowed_app_ids)

    def has_change_permission(self, request, obj=None):
        if request.user.is_superuser:
            return True
        if obj is None:
            return True  # Allow list view
        return UserApplicationAssociation.objects.filter(user=request.user, application=obj).exists()

    def has_view_permission(self, request, obj=None):
        return self.has_change_permission(request, obj)

    def has_delete_permission(self, request, obj=None):
        return self.has_change_permission(request, obj)

    def has_add_permission(self, request):
        return request.user.is_superuser
