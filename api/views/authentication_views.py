import uuid
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.conf import settings
from django.core.mail import EmailMessage
from django.template.loader import render_to_string

from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny
from ..models import User, PasswordHistory, PasswordReset

from ..serializers.authentication_serializer import (
    RegisterUserSerializer,
    LoginUserSerializer,
    ChangePasswordSerializer,
    ForgotPasswordSerializer
)

from api.functools import (
    convert_serializer_errors_from_dict_to_list,
    get_specific_user_with_email,
    check_fields_required,
    convert_to_error_message,
    convert_to_success_message_serialized_data,
    convert_success_message
)


class AuthenticationViewSet(GenericViewSet):
    serializer_class = RegisterUserSerializer
    queryset = User.objects.all()

    def get_queryset(self):
        return User.objects.filter(id=self.request.user.id)

    @action(methods=["POST"], detail=False, url_name="Register User", permission_classes=[AllowAny])
    def register_user(self, request):
        try:
            serialized_input = self.get_serializer(data=request.data)
            if not serialized_input.is_valid():
                return Response(
                    {
                        "message": "failure",
                        "data": "null",
                        "errors": convert_serializer_errors_from_dict_to_list(serialized_input.errors)
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            password = serialized_input.validated_data["password"]
            confirm_password = serialized_input.validated_data["confirm_password"]

            if password != confirm_password:
                return Response(
                    {
                        "message": "failure",
                        "data": "null",
                        "errors": "Password and confirm password does not match"
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            city_and_country = serialized_input.validated_data["city_and_country"]
            city, country = city_and_country.split("/")

            new_user = User(
                first_name=serialized_input.validated_data["first_name"].capitalize(),
                last_name=serialized_input.validated_data["last_name"].capitalize(),
                email=serialized_input.validated_data["email"].lower().strip(),
                phone_number=serialized_input.validated_data["phone_number"].strip(),
                address=serialized_input.validated_data["address"].lower().strip(),
                city=city.capitalize().strip(),
                country=country.capitalize().strip(),
            )

            # Validate user's password with django validators
            try:
                validate_password(password=password, user=new_user)
            except ValidationError as err:
                return Response(
                    {
                        "status": "failure",
                        "data": "null",
                        "error": err
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            # create password history
            password_history = PasswordHistory.objects.create(
                user=new_user,
                password=password
            )

            # set and hash user's password
            new_user.set_password(password)
            new_user.save()

            # create user's token
            token = RefreshToken.for_user(new_user)

            # serialize user object
            serialized_user = self.get_serializer(new_user)

            response = {
                "user": serialized_user.data,
                "token": str(token.access_token)
            }

            return Response(
                {
                    "status": "success",
                    "data": response,
                    "error": "null"
                }
                , status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {
                    "status": "failure",
                    "data": "null",
                    "errors": f"{e}"
                },
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(
        methods=["POST"], detail=False, url_name="user_login",
        permission_classes=[AllowAny], serializer_class=LoginUserSerializer
    )
    def login(self, request):
        try:
            email = request.data["email"]
            password = request.data["password"]

            check_required = check_fields_required(
                {
                    "email": email,
                    "password": password
                }
            )
            if not check_required["status"]:
                return Response(
                    convert_to_error_message(check_required["response"]),
                    status=status.HTTP_400_BAD_REQUEST
                )

            get_user = get_specific_user_with_email(email.lower())
            if not get_user["status"]:
                return Response(
                    convert_to_error_message(get_user["response"]), status=status.HTTP_404_NOT_FOUND
                )
            get_user = get_user["response"]

            if not get_user.check_password(password):
                return Response(
                    convert_to_error_message("Invalid password"),
                    status=status.HTTP_400_BAD_REQUEST
                )

            serialized_user = self.get_serializer(get_user)

            token = RefreshToken.for_user(get_user)
            response = {
                "user": serialized_user.data,
                "token": str(token.access_token)
            }

            return Response(
                convert_to_success_message_serialized_data(response),
                status=status.HTTP_200_OK
            )

        except KeyError as e:
            return Response(
                convert_to_error_message(f"{e}")
                , status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as err:
            return Response(
                convert_to_error_message(f"{err}"),
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(methods=["PUT"], detail=False, url_name="change_user_password", serializer_class=ChangePasswordSerializer)
    def change_password(self, request):
        try:
            #  Get the user object
            user_id = request.user.id
            user = User.objects.get(id=user_id)

            serialized_input = self.get_serializer(data=request.data)
            if not serialized_input.is_valid():
                return Response(
                    convert_to_error_message(serialized_input.errors)
                    , status=status.HTTP_400_BAD_REQUEST
                )

            # Get Input variables
            existing_password = serialized_input.validated_data["existing_password"]
            new_password = serialized_input.validated_data["new_password"]
            confirm_password = serialized_input.validated_data["confirm_password"]

            check_password_valid = user.check_password(existing_password)
            if not check_password_valid:
                return Response(
                    convert_to_error_message("Invalid password entered"),
                    status=status.HTTP_400_BAD_REQUEST
                )

            if new_password != confirm_password:
                return Response(
                    convert_to_error_message("Password Mismatch, check your new password and confirm password entered"),
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Check user's previous password
            if existing_password == new_password:
                return Response(
                    convert_to_error_message("New password is the same with existing password"),
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate user's password with django validators
            try:
                validate_password(password=new_password, user=user)
            except ValidationError as err:
                return Response(
                    convert_to_error_message(err),
                    status=status.HTTP_400_BAD_REQUEST
                )

            # delete user's password history
            PasswordHistory.objects.filter(user=user).delete()

            # create password history
            password_history = PasswordHistory.objects.create(
                user=user,
                password=new_password,
            )

            user.set_password(new_password)
            user.save()

            return Response(
                convert_success_message("Password updated successfully"),
                status=status.HTTP_200_OK
            )

        except KeyError as e:
            return Response(
                convert_to_error_message(f"{e}")
                , status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as err:
            return Response(
                convert_to_error_message(f"{err}"),
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(methods=["POST"], detail=False, url_name="user_forgot_password_request", permission_classes=[AllowAny])
    def forgot_password_request(self, request):
        try:
            email = request.data["email"]
            check_required = check_fields_required(
                {"email": email}
            )
            if not check_required["status"]:
                return Response(
                    convert_to_error_message(check_required["response"]),
                    status=status.HTTP_400_BAD_REQUEST
                )

            get_user = get_specific_user_with_email(email.lower())
            if not get_user["status"]:
                return Response(
                    convert_to_error_message(get_user["response"]), status=status.HTTP_404_NOT_FOUND
                )
            user = get_user["response"]

            token = "{}".format(uuid.uuid4().int >> 90)
            token = token[:6]
            PasswordReset.objects.filter(user=user).delete()
            get = PasswordReset.objects.create(user=user, token=token)

            # try:
            subject = "Password Reset code"
            from_email = settings.DEFAULT_FROM_EMAIL
            body = render_to_string(
                "email/password_reset.html", {
                    "token": token,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                }
            )
            message = EmailMessage(
                subject,
                body,
                to=[user.email],
                from_email=from_email,
            )
            message.content_subtype = "html"
            message.send(fail_silently=True)
            get.sent = True
            get.save()

            return Response(convert_success_message("Password Reset request successful"), status=status.HTTP_200_OK)

        except KeyError as e:
            return Response(
                convert_to_error_message(f"{e}")
                , status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as err:
            return Response(
                convert_to_error_message(f"{err}"),
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(
        methods=["POST"], detail=False, url_name="confirm_forgot_password", serializer_class=ForgotPasswordSerializer,
        permission_classes=[AllowAny]
    )
    def confirm_forgot_password(self, request):
        try:
            serialized_input = self.get_serializer(data=request.data)
            if not serialized_input.is_valid():
                return Response(
                    convert_to_error_message(serialized_input.errors)
                    , status=status.HTTP_400_BAD_REQUEST
                )

            token = serialized_input.validated_data["token"]
            new_password = serialized_input.validated_data["new_password"]
            confirm_password = serialized_input.validated_data["confirm_password"]

            get_record_of_password_reset = PasswordReset.objects.get(token=token)
            user = get_record_of_password_reset.user

            check_formal_password = PasswordHistory.objects.filter(user=user, password=new_password)
            if check_formal_password.exists():
                return Response(
                    convert_to_error_message(
                        "New password entered is your formal password, Please try and Login with it"
                    ),
                    status=status.HTTP_400_BAD_REQUEST
                )

            if new_password != confirm_password:
                return Response(
                    convert_to_error_message(
                        "Password Mismatch, check your new password and confirm password entered"
                    ),
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate user's password with django validators
            try:
                validate_password(password=new_password, user=user)
            except ValidationError as err:
                return Response(
                    convert_to_error_message(err),
                    status=status.HTTP_400_BAD_REQUEST
                )

            # delete user's password history
            PasswordHistory.objects.filter(user=user).delete()

            # create password history
            password_history = PasswordHistory.objects.create(
                user=user,
                password=new_password,
            )

            user.set_password(new_password)
            user.save()

            return Response(
                convert_success_message("Password updated successfully"),
                status=status.HTTP_200_OK
            )

        except PasswordReset.DoesNotExist:
            return Response(
                convert_to_error_message("Invalid Token entered")
            )

        except KeyError as e:
            return Response(
                convert_to_error_message(f"{e}")
                , status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as err:
            return Response(
                convert_to_error_message(f"{err}"),
                status=status.HTTP_400_BAD_REQUEST
            )
