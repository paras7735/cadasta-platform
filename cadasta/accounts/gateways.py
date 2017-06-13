from twilio.rest import Client
from django.utils.translation import ugettext as _
from django.conf import settings
import logging

# add logger to settings to display messages in the console
logger = logging.getLogger(__name__)


class TwilioSMS(object):

    def __init__(self):
        self.client = Client(
            account=getattr(settings, 'TWILIO_ACCOUNT_SID'),
            token=getattr(settings, 'TWILIO_AUTH_TOKEN')
        )

    def send_sms(self, phone, message):
        self.client.messages.create(
            to=phone,
            from_=getattr(settings, 'TWILIO_CALLER_ID'),
            body=_(message))


class Fake(object):
    @staticmethod
    def send_sms(self, phone, message):
        logger.info('Fake SMS to: %s. "%s"' % (self.phone, self.message))
