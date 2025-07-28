import uuid
from django.db import models
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.contrib.postgres.fields import ArrayField
from django.db.models import JSONField
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.conf import settings
from datetime import timedelta

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Users must have an email address')
        email = self.normalize_email(email)
        extra_fields.setdefault('user_registry_id', uuid.uuid4())  # ensure it's filled
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_admin', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)



class User(AbstractBaseUser, PermissionsMixin):  
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # user_registry_id = models.UUIDField(unique=True)
    user_registry_id = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(max_length=255, unique=True, null=True, blank=True)
    phone_num = models.CharField(max_length=255, null=True, blank=True)
    access_token = models.CharField(max_length=255, null=True, blank=True)
    refresh_token = models.CharField(max_length=255, null=True, blank=True)
    # coordinates = models.JSONField(null=True, blank=True)
    coordinates = models.TextField(null=True, blank=True)
    product_offer_id = models.UUIDField(null=True, blank=True)
    cart_id = models.UUIDField(null=True, blank=True)
    stripe_customer_id = models.CharField(max_length=255, unique=True, null=True, blank=True)
    is_admin = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email

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
        verbose_name = "Field"
        verbose_name_plural = "Fields"
        
        
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
        verbose_name = "User Field"
        verbose_name_plural = "User Fields"


# class Application(models.Model):
#     id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

#     type = ArrayField(models.CharField(max_length=50), null=True, blank=True)
#     description = models.TextField(null=True, blank=True)
#     authors = ArrayField(models.CharField(max_length=100), null=True, blank=True)
#     company = models.CharField(max_length=255, null=True, blank=True)
#     create_date = models.DateTimeField(auto_now_add=True)
#     picture = models.TextField(null=True, blank=True)
#     dev_stage = models.CharField(max_length=100, null=True, blank=True)
#     price_scope_month = models.FloatField(null=True, blank=True)
#     root = models.CharField(max_length=255, unique=True)
#     meta_data = JSONField(null=True, blank=True)  # must be jsonb now in DB

#     def __str__(self):
#         return self.root

#     class Meta:
#         db_table = "applications"


class Application(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    type = ArrayField(models.CharField(max_length=50), null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    authors = ArrayField(models.CharField(max_length=100), null=True, blank=True)
    company = models.CharField(max_length=255, null=True, blank=True)
    create_date = models.DateTimeField(auto_now_add=True)
    picture = models.TextField(null=True, blank=True)
    dev_stage = models.CharField(max_length=100, null=True, blank=True)
    price_scope_month = models.FloatField(null=True, blank=True)
    root = models.CharField(max_length=255, unique=True)  # this is your identifier
    meta_data = JSONField(null=True, blank=True)
    

    def __str__(self):
        return self.root

    class Meta:
        db_table = "applications"


class UserApplicationAssociation(models.Model):
    user = models.ForeignKey(
        User,
        to_field='user_registry_id',
        on_delete=models.CASCADE,
    )
    application = models.ForeignKey(
        'Application', 
        to_field='id',
        on_delete=models.CASCADE,
        db_column='application_id'
    )
    creation_date = models.DateTimeField(null=True, blank=True)
    served_data_size = models.FloatField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    unique_id = models.IntegerField(null=True, blank=True)
    api_called = models.JSONField(null=True, blank=True)

    class Meta:
        db_table = 'user_application_association'
        unique_together = ('user', 'application')




# class UserApplicationAssociation(models.Model):
#     user = models.ForeignKey(User, on_delete=models.CASCADE)
#     application = models.ForeignKey(Application, on_delete=models.CASCADE)
#     creation_date = models.DateTimeField()
#     served_data_size = models.CharField(max_length=255)
#     is_active = models.BooleanField(default=True)
#     # api_called = models.JSONField(default=dict)
#     api_called = models.TextField(default='{}')


#     def __str__(self):
#         return f"{self.user.email} - {self.application.name}"
    
#     class Meta:
#         db_table = "user_application_association"




class UserAuthorizationsAccess(models.Model):
    
    
    VISIBILITY_CHOICES = (
        ('public', 'Public'),
        ('private', 'Private'),
    )
    user = models.ForeignKey(
        User,
        to_field='user_registry_id',
        on_delete=models.CASCADE,
    )
    application = models.ForeignKey(Application, on_delete=models.CASCADE)
    is_active = models.BooleanField(default=False, help_text="Toggle access to APIs")
    visibility = models.CharField(max_length=10, choices=VISIBILITY_CHOICES, default='private') 
    created_at = models.DateTimeField(auto_now=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('user', 'application')
        db_table = 'user_authorizations_access'
        verbose_name = "User Authorization Access"
        verbose_name_plural = "User Authorization Access"

    def __str__(self):
        user_email = self.user.email if self.user else "Unknown User"
        app_name = self.application.root if self.application else "Unknown App"
        status = "Active" if self.is_active else "Inactive"
        return f"{user_email} - {app_name} ({status})"


class S2CellToken(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    cell_token = models.TextField(unique=True)

    def __str__(self):
        return self.cell_token
    
    class Meta:
        db_table = 's2_cell_tokens'
        
        
class GeoIDs(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    geo_id = models.CharField(max_length=255, unique=True, null=True, blank=True)
    # geo_data = models.JSONField(null=True, blank=True)
    geo_data = models.TextField(null=True,blank=True)
    authority_token = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(null=True, blank=True)
    country = models.CharField(max_length=255, null=True, blank=True)
    boundary_type = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        db_table = 'geo_ids'  # Ensures Django maps this model to the existing table
        managed = False       # So Django won't try to create or alter this table
        
        
class CellsGeoID(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    geo_id = models.ForeignKey(
        'GeoIDs',
        db_column='geo_id',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )

    cell_id = models.ForeignKey(
        'S2CellToken',
        db_column='cell_id',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )

    class Meta:
        db_table = 'cells_geo_ids'
        managed = False  # Prevent Django from creating/dropping this table
        
        
class CellsGeosMiddle(models.Model):
    geo = models.ForeignKey(GeoIDs, on_delete=models.CASCADE, related_name='cell_links')
    s2celltoken = models.ForeignKey(S2CellToken, on_delete=models.CASCADE, related_name='geo_links')


class ProductPlan(models.Model):
    PLAN_CHOICES = [
        ('free', 'Free'),
        ('plus', 'Plus'),
        ('pro', 'Pro'),
    ]
    name = models.CharField(max_length=20, choices=PLAN_CHOICES, unique=True)
    price = models.DecimalField(max_digits=6, decimal_places=2, default=0.00)
    description = models.TextField(blank=True, null=True)
    features = models.JSONField(default=list)  # Example: ["Access to one scope", "Unlimited fields"]

    def __str__(self):
        return f"{self.get_name_display()} - ${self.price}/month"


class UserSubscription(models.Model):
    user_id = models.UUIDField()
    plan = models.ForeignKey(ProductPlan, on_delete=models.SET_NULL, null=True)
    start_date = models.DateTimeField(default=timezone.now)
    end_date = models.DateTimeField(blank=True, null=True)
    active = models.BooleanField(default=False)
    stripe_payment_id = models.CharField(max_length=255, blank=True, null=True)

    def set_plan(self, plan: ProductPlan):
        """Assign a new plan with start/end dates."""
        self.plan = plan
        self.start_date = timezone.now()
        if plan.name != 'free':
            self.end_date = timezone.now() + timedelta(days=30)
        else:
            self.end_date = None
        self.active = True
        self.save()

    def __str__(self):
        return f"User {self.user_id} - {self.plan}"
    

# from dashboard.models import ProductPlan
# ProductPlan.objects.get_or_create(name='free', price=0, features=["Access to one scope", "Access to one field"])
# ProductPlan.objects.get_or_create(name='plus', price=10, features=["Access to one scope", "Unlimited fields"])
# ProductPlan.objects.get_or_create(name='pro', price=30, features=["Unlimited scopes", "Unlimited fields"])
