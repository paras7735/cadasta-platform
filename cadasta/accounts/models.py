from django.conf import settings
from django.db import models
from django.dispatch import receiver
from django.utils.translation import ugettext as _
from django.core.mail import send_mail
from django.template.loader import render_to_string
import django.contrib.auth.models as auth
import django.contrib.auth.base_user as auth_base
from allauth.account.signals import password_changed, password_reset
from tutelary.models import Policy
from tutelary.decorators import permissioned_model
from django_otp.models import Device
from django_otp.oath import TOTP
from django_otp.util import random_hex, hex_validator
from binascii import unhexlify
from .gateways import TwilioSMS

from simple_history.models import HistoricalRecords
from .manager import UserManager


PERMISSIONS_DIR = settings.BASE_DIR + '/permissions/'


def abstract_user_field(name):
    for f in auth.AbstractUser._meta.fields:
        if f.name == name:
            return f


@permissioned_model
class User(auth_base.AbstractBaseUser, auth.PermissionsMixin):
    username = abstract_user_field('username')
    full_name = models.CharField(_('full name'), max_length=130, blank=True)
    email = abstract_user_field('email')
    is_staff = abstract_user_field('is_staff')
    is_active = abstract_user_field('is_active')
    date_joined = abstract_user_field('date_joined')
    email_verified = models.BooleanField(default=False)
    # verify_email_by = models.DateTimeField(default=now_plus_48_hours)
    phone = models.CharField(max_length=12, unique=True, blank=True)
    phone_verified = models.BooleanField(default=False)
    change_pw = models.BooleanField(default=True)

    objects = UserManager()

    history = HistoricalRecords()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email' or 'phone', 'full_name']

    class Meta:
        ordering = ('username',)
        verbose_name = _('user')
        verbose_name_plural = _('users')

    objects = UserManager()

    class TutelaryMeta:
        perm_type = 'user'
        path_fields = ('username',)
        actions = [('user.list',
                    {'permissions_object': None,
                     'error_message':
                     _("You don't have permission to view user details")}),
                   ('user.update',
                    {'error_message':
                     _("You don't have permission to update user details")})]

    def __repr__(self):
        repr_string = ('<User username={obj.username}'
                       ' full_name={obj.full_name}'
                       ' email={obj.email}'
                       ' email_verified={obj.email_verified}'
                       ' phone={obj.phone}'
                       ' phone_verified={obj.phone_verified}>')
        return repr_string.format(obj=self)

    def get_display_name(self):
        """
        Returns the display name.
        If full name is present then return full name as display name
        else return username.
        """
        if self.full_name != '':
            return self.full_name
        else:
            return self.username


@receiver(models.signals.post_save, sender=User)
def assign_default_policy(sender, instance, **kwargs):
    policy = Policy.objects.get(name='default')
    assigned_policies = instance.assigned_policies()
    if policy not in assigned_policies:
        assigned_policies.insert(0, policy)
    instance.assign_policies(*assigned_policies)


@receiver(password_changed)
@receiver(password_reset)
def password_changed_reset(sender, request, user, **kwargs):
    msg_body = render_to_string(
        'accounts/email/password_changed_notification.txt')
    send_mail(
        _("Change of password at Cadasta Platform"),
        msg_body,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=False
    )


def default_key():
    return random_hex(20)


class VerificationDevice(Device):
    secret_key = models.CharField(
        max_length=40,
        default=default_key,
        validators=[hex_validator],
        help_text="Hex-encoded secret key to generate totp tokens.")
    user = models.ForeignKey(User)

    step = getattr(settings, 'TOTP_TOKEN_VALIDITY')
    digits = getattr(settings, 'TOTP_DIGITS')

    class Meta(Device.Meta):
        verbose_name = "Verification Device"

    @property
    def bin_key(self):
        return unhexlify(self.secret_key.encode())

    def totp_obj(self):
        totp = TOTP(key=self.bin_key, step=self.step, digits=self.digits)
        return totp

    def generate_token(self):
        totp = self.totp_obj()
        token = totp.token()
        message = "Your Cadasta Token is %s. It is valid for %s minutes." % (
            token, getattr(settings, 'TOTP_TOKEN_VALIDITY') * 60)

        twilio_obj = TwilioSMS()
        twilio_obj.send_sms(phone=self.user.phone, message=message)

    def verify_token(self, token):
        totp = self.totp_obj()
        if totp.verify(token, tolerance=0):
            self.user.phone_verified = True
        else:
            self.user.phone_verified = False

        return self.user.phone_verified
