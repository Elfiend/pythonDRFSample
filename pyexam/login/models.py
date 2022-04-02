from django.conf import settings
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.utils.translation import gettext_lazy as _


class LocalUserManager(BaseUserManager):
    """
    The manager for the LocalUser with email as the key.
    """

    def create_user(self, email, password=None):
        """
        Creates and saves a User with the given email and password.
        """
        if not email:
            raise ValueError('Users must have an email address')

        user = self.model(email=self.normalize_email(email))

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None):
        """
        Creates and saves a superuser with the given email and password.
        """
        user = self.create_user(
            email,
            password=password,
        )
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


class LocalUser(AbstractUser):
    """
    The user with email as the key.
    """
    username = None
    email = models.EmailField(
        _('email address'),
        max_length=255,
        unique=True,
    )

    login_count = models.PositiveIntegerField(default=0)
    email_confirmed = models.BooleanField(default=True)
    is_social_auth = models.BooleanField(default=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = LocalUserManager()

    class Meta:
        ordering = ['email']

    def __str__(self):
        return self.email


class Profile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL,
                                on_delete=models.CASCADE)
    social_name = models.CharField(_('Social name'), max_length=150, blank=True)
