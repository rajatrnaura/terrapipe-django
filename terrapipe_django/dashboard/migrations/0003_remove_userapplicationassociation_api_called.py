# Generated by Django 4.2.23 on 2025-06-18 09:48

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0002_create_user_authorizations_access'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='userapplicationassociation',
            name='api_called',
        ),
    ]
