import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator
from django.utils import timezone


class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4(), editable=False)
    username = models.CharField(max_length=255, null=True, unique=True)
    phone_regex = RegexValidator(
        regex=r"^\+?1?\d{9,15}$",
        message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed.",
    )
    phone_number = models.CharField(
        validators=[phone_regex], max_length=17, null=True, blank=True
    )
    address = models.CharField(max_length=255, null=True, blank=True)
    city = models.CharField(max_length=150, null=True, blank=True)
    country = models.CharField(max_length=150, null=True, blank=True)

    class Meta:
        ordering = ["-date_joined"]


def set_username(sender, instance, **kwargs):
    if not instance.username:
        email = instance.email
        split_email = email.split("@")
        username = split_email[0]
        counter = 1
        while User.objects.filter(username=username).exists():
            username = username + str(counter)
            counter += 1
        instance.username = username
        return username


models.signals.pre_save.connect(set_username, sender=User)


class PasswordHistory(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4(), editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="user_password_history")
    password = models.CharField(max_length=128)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.user.email


class PasswordReset(models.Model):
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name="user_password_code"
    )
    token = models.CharField(max_length=9, unique=True)
    sent = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    @property
    def check_expire(self):
        diff = timezone.now() - self.created_at
        days, seconds = diff.days, diff.seconds
        hours = days * 24 + seconds // 3600
        if hours > 4:
            return True
        else:
            return False
