
from django.db import migrations

class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0006_alter_user_user_registry_id'),
    ]

    operations = [
        migrations.RunSQL(
            sql="",
            reverse_sql="ALTER TABLE users DROP CONSTRAINT IF EXISTS user_registry_id_unique;"
        )


    ]
