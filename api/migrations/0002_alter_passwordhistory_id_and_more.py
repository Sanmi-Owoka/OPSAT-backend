# Generated by Django 4.2 on 2024-01-11 10:53

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="passwordhistory",
            name="id",
            field=models.UUIDField(
                default=uuid.UUID("6a89df49-a3b9-459c-8c48-61352e8c425a"),
                editable=False,
                primary_key=True,
                serialize=False,
            ),
        ),
        migrations.AlterField(
            model_name="passwordhistory",
            name="password",
            field=models.CharField(max_length=128),
        ),
        migrations.AlterField(
            model_name="user",
            name="id",
            field=models.UUIDField(
                default=uuid.UUID("3515f20c-cce1-4776-9326-e408f14286de"),
                editable=False,
                primary_key=True,
                serialize=False,
            ),
        ),
    ]
