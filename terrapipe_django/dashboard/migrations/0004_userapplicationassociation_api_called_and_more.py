# Generated by Django 4.2.23 on 2025-06-18 12:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0003_remove_userapplicationassociation_api_called'),
    ]

    operations = [
        migrations.AddField(
            model_name='userapplicationassociation',
            name='api_called',
            field=models.JSONField(blank=True, default=dict, null=True),
        ),
        migrations.AlterField(
            model_name='user',
            name='coordinates',
            field=models.TextField(blank=True, null=True),
        ),
    ]
