from django.db import models
import uuid
from django.contrib.auth.models import PermissionsMixin, UserManager
from django.contrib.auth.base_user import AbstractBaseUser

class CustomUserManager(UserManager):
    def create_user(self, email, user_registry_id, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, user_registry_id=user_registry_id, **extra_fields)
        if password:
            user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, user_registry_id, password=None, **extra_fields):
        extra_fields.setdefault('is_admin', True)
        return self.create_user(email, user_registry_id, password, **extra_fields)

class ProductOffer(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        managed = False
        db_table = 'product_offers'

    def __str__(self):
        return self.name

class User(AbstractBaseUser, PermissionsMixin):
    user_registry_id = models.CharField(max_length=36, unique=True)
    email = models.EmailField(unique=True)
    phone_num = models.CharField(max_length=15, null=True, blank=True)
    coordinates = models.JSONField(null=True, blank=True)
    product_offer_id = models.UUIDField(null=True, blank=True)
    access_token = models.TextField(null=True, blank=True)
    refresh_token = models.TextField(null=True, blank=True)
    is_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField()
    updated_at = models.DateTimeField(auto_now=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['user_registry_id']

    class Meta:
        managed = False
        db_table = 'users'

    def __str__(self):
        return self.email

    groups = models.ManyToManyField(
        'auth.Group',
        verbose_name='groups',
        blank=True,
        help_text='The groups this user belongs to.',
        related_name='custom_user_set',
        related_query_name='custom_user',
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        verbose_name='user permissions',
        blank=True,
        help_text='Specific permissions for this user.',
        related_name='custom_user_set',
        related_query_name='custom_user',
    )

class RegistryUser(models.Model):
    id = models.CharField(max_length=36, primary_key=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
    phone_num = models.CharField(max_length=15, null=True, blank=True)
    lat_lng = models.JSONField(null=True, blank=True)
    device_id = models.CharField(max_length=255, null=True, blank=True)
    access_token = models.TextField(null=True, blank=True)
    refresh_token = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField()
    updated_at = models.DateTimeField()
    activated = models.BooleanField(default=False)

    class Meta:
        managed = False
        db_table = 'users'

class Limits(models.Model):
    user_registry_id = models.CharField(max_length=36, unique=True)
    max_device = models.IntegerField(default=1)
    max_api_key = models.IntegerField(default=1)
    max_request = models.IntegerField(default=100)

    class Meta:
        managed = False
        db_table = 'limits'