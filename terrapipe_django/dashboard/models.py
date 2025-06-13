# dashboard/models.py
from django.db import models
import uuid
from django.utils import timezone

import uuid

class User(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_registry_id = models.UUIDField(unique=True, null=True)
    email = models.EmailField(unique=True, null=True)
    phone_num = models.CharField(max_length=15, null=True, blank=True)
    coordinates = models.CharField(max_length=255, null=True, blank=True)
    is_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.email or str(self.user_registry_id)

class UserFields(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.UUIDField(null=False)
    field_id = models.UUIDField(null=False)
    field_name = models.CharField(max_length=255, null=True)  # Adjust max_length as needed
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = 'users_fields'  # Match the existing table name
        managed = False  # Tell Django not to manage this table
        unique_together = ('user_id', 'field_id')  # Match the unique constraint
        constraints = [
            models.UniqueConstraint(fields=['user_id', 'field_id'], name='unique_user_id_field_id')
        ]

    def save(self, *args, **kwargs):
        # Update the updated_at field on save
        self.updated_at = timezone.now()
        super().save(*args, **kwargs)

    def __str__(self):
        return f'<id {self.id}>'
    
    
class Fields(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    geo_id = models.CharField(max_length=255, null=True)
    created_at = models.DateTimeField(null=True)
    updated_at = models.DateTimeField(null=True)

    class Meta:
        db_table = 'fields'
        managed = False
        constraints = [
            models.UniqueConstraint(fields=['id', 'geo_id'], name='unique_field_geo_id')
        ]

    def __str__(self):
        return f'<id {self.id}>'