from django.contrib import admin
from .models import User , UserFields , Fields , Application

# Register your models here.

# admin.site.register(User)
admin.site.register(UserFields)
admin.site.register(Fields)
# @admin.register(Application)
