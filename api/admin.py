from django.contrib import admin
from django.contrib.auth import admin as auth_admin
from .models import User
from .forms import UserChangeForm, UserCreationForm


@admin.register(User)
class UserAdmin(auth_admin.UserAdmin):
    form = UserChangeForm
    add_form = UserCreationForm
    fieldsets = (
                    (
                        "Avatar  info",
                        {
                            "fields": (
                                "username"
                                "phone_number",
                                "address",
                                "city",
                                "country",
                            )
                        },
                    ),
                ) + auth_admin.UserAdmin.fieldsets
    list_display = [
        "id",
        "first_name",
        "last_name",
        "email",
        "phone_number",
        "username",
        "date_joined",
    ]

    search_fields = [
        "email",
    ]
