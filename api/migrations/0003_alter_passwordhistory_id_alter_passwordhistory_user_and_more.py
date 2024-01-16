# Generated by Django 4.2 on 2024-01-16 12:28

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0002_alter_passwordhistory_id_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="passwordhistory",
            name="id",
            field=models.UUIDField(
                default=uuid.UUID("f2b84f73-f8a1-42ed-aabf-cf7746228681"),
                editable=False,
                primary_key=True,
                serialize=False,
            ),
        ),
        migrations.AlterField(
            model_name="passwordhistory",
            name="user",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="user_password_history",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AlterField(
            model_name="user",
            name="id",
            field=models.UUIDField(
                default=uuid.UUID("0b5502a4-6d57-4a05-8b5d-aa6e6a24d02b"),
                editable=False,
                primary_key=True,
                serialize=False,
            ),
        ),
        migrations.CreateModel(
            name="PasswordReset",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("token", models.CharField(max_length=9, unique=True)),
                ("sent", models.BooleanField(default=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "user",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="user_password_code",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
    ]
