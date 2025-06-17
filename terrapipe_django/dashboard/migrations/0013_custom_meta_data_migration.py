from django.db import migrations, models
from django.contrib.postgres.fields import JSONField

def migrate_meta_data_to_jsonb(apps, schema_editor):
    # Use raw SQL to convert json[] to jsonb
    with schema_editor.connection.cursor() as cursor:
        # Transform meta_data (json[]) to meta_data_new (jsonb)
        # Extract the first element of the array and parse it as JSON
        cursor.execute("""
            UPDATE applications
            SET meta_data_new = CASE
                WHEN meta_data IS NOT NULL AND array_length(meta_data, 1) > 0 THEN
                    (meta_data[1]::text)::jsonb
                ELSE NULL
            END
            WHERE meta_data IS NOT NULL;
        """)

def reverse_migrate_meta_data(apps, schema_editor):
    # Reverse: convert jsonb back to json[] (wrap in an array)
    with schema_editor.connection.cursor() as cursor:
        cursor.execute("""
            UPDATE applications
            SET meta_data = ARRAY[meta_data_new::text::json]
            WHERE meta_data_new IS NOT NULL;
        """)

class Migration(migrations.Migration):
    dependencies = [
        ('dashboard', '0012_alter_application_options_alter_application_authors_and_more'),
    ]

    operations = [
        # Add a temporary column for jsonb
        migrations.AddField(
            model_name='Application',
            name='meta_data_new',
            field=JSONField(null=True, blank=True),
        ),
        # Copy and transform data from meta_data to meta_data_new
        migrations.RunPython(migrate_meta_data_to_jsonb, reverse_migrate_meta_data),
        # Remove the old meta_data column
        migrations.RemoveField(
            model_name='Application',
            name='meta_data',
        ),
        # Rename meta_data_new to meta_data
        migrations.RenameField(
            model_name='Application',
            old_name='meta_data_new',
            new_name='meta_data',
        ),
    ]
