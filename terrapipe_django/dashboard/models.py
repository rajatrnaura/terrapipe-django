import uuid
from django.db import models
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.contrib.postgres.fields import ArrayField
from django.db.models import JSONField
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager


class CustomUserManager(BaseUserManager):
    def create_user(self, user_registry_id, email=None, password=None, **extra_fields):
        if not user_registry_id:
            raise ValueError('The user_registry_id must be set')
        user = self.model(user_registry_id=user_registry_id, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, user_registry_id, email=None, password=None, **extra_fields):
        extra_fields.setdefault('is_admin', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(user_registry_id, email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):  # ✅ Must inherit these two
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_registry_id = models.UUIDField(unique=True)
    email = models.EmailField(max_length=255, unique=True, null=True, blank=True)
    phone_num = models.CharField(max_length=255, null=True, blank=True)
    access_token = models.CharField(max_length=255, null=True, blank=True)
    refresh_token = models.CharField(max_length=255, null=True, blank=True)
    coordinates = models.JSONField(null=True, blank=True)
    product_offer_id = models.UUIDField(null=True, blank=True)
    cart_id = models.UUIDField(null=True, blank=True)
    stripe_customer_id = models.CharField(max_length=255, unique=True, null=True, blank=True)
    is_admin = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'user_registry_id'  # ✅ Required
    REQUIRED_FIELDS = ['email']  # ✅ Required

    def __str__(self):
        return self.email or str(self.user_registry_id)

    class Meta:
        db_table = 'users'

class Fields(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    geo_id = models.CharField(max_length=255, null=True)
    created_at = models.DateTimeField(null=True)
    updated_at = models.DateTimeField(null=True)

    def __str__(self):
        return f'<{self.id}>'

    class Meta:
        db_table = 'fields'
        managed = False
        constraints = [
            models.UniqueConstraint(fields=['id', 'geo_id'], name='unique_field_geo_id')
        ]

class UserFields(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey('User', on_delete=models.CASCADE, db_column='user_id')
    field = models.ForeignKey('Fields', on_delete=models.CASCADE, db_column='field_id')
    field_name = models.CharField(max_length=255, null=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f'<{self.id}>'

    def save(self, *args, **kwargs):
        self.updated_at = timezone.now()
        super().save(*args, **kwargs)

    class Meta:
        db_table = 'users_fields'
        managed = False
        unique_together = ('user', 'field')
        constraints = [
            models.UniqueConstraint(fields=['user', 'field'], name='unique_user_id_field_id')
        ]


User = get_user_model()

class Application(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    type = ArrayField(models.CharField(max_length=50))  # character varying(50)[]
    description = models.TextField()
    authors = ArrayField(models.CharField(max_length=100))  # character varying(100)[]
    company = models.CharField(max_length=100, null=True, blank=True)
    create_date = models.DateTimeField(null=True, blank=True)
    picture = models.TextField(null=True, blank=True)
    dev_stage = models.CharField(max_length=50)
    price_scope_month = models.FloatField(null=True, blank=True)
    root = models.CharField(max_length=255, unique=True)
    meta_data = ArrayField(JSONField(), null=True, blank=True)  # json[]

    class Meta:
        db_table = 'applications'
        verbose_name = 'Application'
        verbose_name_plural = 'Applications'

    def __str__(self):
        return self.root


class UserApplicationAssociation(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    application = models.ForeignKey(Application, on_delete=models.CASCADE)
    creation_date = models.DateTimeField(null=True, blank=True)
    api_called = models.IntegerField(null=True, blank=True)
    served_data_size = models.FloatField(null=True, blank=True)

    class Meta:
        db_table = 'user_application_association'
        unique_together = ('user', 'application')
        verbose_name = 'User Application Association'
        verbose_name_plural = 'User Application Associations'

    def __str__(self):
        return f"{self.user} - {self.application.root}"