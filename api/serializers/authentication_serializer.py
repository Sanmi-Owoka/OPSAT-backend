from rest_framework import serializers
from api.models import User


class RegisterUserSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(required=True, max_length=50, trim_whitespace=True)
    last_name = serializers.CharField(required=True, max_length=50, trim_whitespace=True)
    email = serializers.EmailField(required=True)
    phone_number = serializers.CharField(required=True, max_length=20, trim_whitespace=True)
    address = serializers.CharField(required=True, max_length=150, trim_whitespace=True)
    city_and_country = serializers.CharField(required=True, max_length=150, trim_whitespace=True, write_only=True)
    password = serializers.CharField(
        required=True, max_length=150, min_length=4, trim_whitespace=True, write_only=True)
    confirm_password = serializers.CharField(
        required=True, max_length=150, min_length=4, trim_whitespace=True, write_only=True
    )

    class Meta:
        model = User
        fields = [
            "id",
            "first_name",
            "last_name",
            "email",
            "phone_number",
            "address",
            "city_and_country",
            "password",
            "confirm_password",
            "date_joined",
            "username",
            "city",
            "country",
        ]
        read_only_fields = [
            "id",
            "date_joined",
            "username",
            "city",
            "country"
        ]
        extra_kwargs = {
            "password": {"write_only": True},
            "confirm_password": {"write_only": True},
            "city_and_country": {"write_only": True},
        }


class LoginUserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(
        required=True, max_length=150, min_length=4, trim_whitespace=True, write_only=True
    )

    class Meta:
        model = User
        fields = [
            "id",
            "first_name",
            "last_name",
            "email",
            "phone_number",
            "address",
            "password",
            "date_joined",
            "username",
            "city",
            "country",
        ]
        read_only_fields = [
            "id",
            "first_name",
            "last_name",
            "email",
            "phone_number",
            "address",
            "date_joined",
            "username",
            "city",
            "country",
        ]


class ChangePasswordSerializer(serializers.ModelSerializer):
    existing_password = serializers.CharField(
        required=True, max_length=150, min_length=4, trim_whitespace=True, write_only=True
    )
    new_password = serializers.CharField(
        required=True, max_length=150, min_length=4, trim_whitespace=True, write_only=True
    )
    confirm_password = serializers.CharField(
        required=True, max_length=150, min_length=4, trim_whitespace=True, write_only=True
    )

    class Meta:
        model = User
        fields = [
            "existing_password",
            "new_password",
            "confirm_password",
        ]


class ForgotPasswordSerializer(serializers.ModelSerializer):
    token = serializers.CharField(
        required=True, max_length=150, min_length=4, trim_whitespace=True, write_only=True
    )
    new_password = serializers.CharField(
        required=True, max_length=150, min_length=4, trim_whitespace=True, write_only=True
    )
    confirm_password = serializers.CharField(
        required=True, max_length=150, min_length=4, trim_whitespace=True, write_only=True
    )

    class Meta:
        model = User
        fields = [
            "token",
            "new_password",
            "confirm_password",
        ]
