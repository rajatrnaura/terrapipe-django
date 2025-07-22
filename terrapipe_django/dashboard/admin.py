from django.contrib import admin
from django.contrib.auth import get_user_model
from .models import Application, UserAuthorizationsAccess

User = get_user_model()

@admin.register(User)
class CustomUserAdmin(admin.ModelAdmin):
    search_fields = ['email']
    list_display = ('email',)  # Ensure email list displays

    def get_queryset(self, request):
        return super().get_queryset(request)  # Remove defer('coordinates')
    
@admin.register(Application)
class ApplicationAdmin(admin.ModelAdmin):
    list_display = ('root',)
    search_fields = ('root',)
    
from django.core.exceptions import ValidationError

@admin.register(UserAuthorizationsAccess)
class UserAuthorizationsAccessAdmin(admin.ModelAdmin):
    list_display = ('get_user_email', 'application', 'is_active', 'visibility', 'updated_at')  # 👈 add visibility
    list_filter = ('is_active', 'application', 'visibility')  # 👈 add visibility filter
    search_fields = ('user__email', 'application__root')
    fields = ('user', 'application', 'is_active', 'visibility')  # 👈 visibility shown in form

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user', 'application')

    def get_user_email(self, obj):
        return obj.user.email if obj.user else "Unknown User"
    get_user_email.short_description = 'User Email'

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == 'user':
            kwargs['queryset'] = User.objects.all()
        return super().formfield_for_foreignkey(db_field, request, **kwargs)

    def save_model(self, request, obj, form, change):
        if not User.objects.filter(user_registry_id=obj.user_id).exists():
            raise ValidationError("Selected user does not exist in the database.")
        super().save_model(request, obj, form, change)

