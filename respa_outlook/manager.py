from exchangelib import Account, Credentials, EWSDateTime, EWSTimeZone, IMPERSONATION, DELEGATE, Configuration
from exchangelib.errors import ErrorSchemaValidation, ErrorImpersonateUserDenied, ErrorAccessDenied
from datetime import datetime, timedelta
from time import sleep

from threading import Lock

import logging

logger = logging.getLogger()


class RespaOutlookManager:
    def __init__(self, configuration):
        self.configuration = configuration
        self.account = None
        self.pop_from_store = False
        self.failed = False
        self.reported = False
        try:
            self.account = self._get_account()
            self.calendar = self.account.calendar
            self.future()[0]
        except ErrorAccessDenied:
            logger.warning("Configuration email: \"%(config_email)s\" does not have the permission to access resource \"%(resource)s\" email: \"%(resource_email)s\"" % ({
                'config_email': self.configuration.email,
                'resource': self.configuration.resource.name,
                'resource_email': self.configuration.resource.resource_email
            }))
            self.failed = True

    def future(self):
        return self.account.calendar.filter(end__gte=ToEWSDateTime(datetime.now().replace(microsecond=0)))

    def _get_account(self):
        resource = self.configuration.resource
        if not self.account:
            self.account = Account(primary_smtp_address=resource.resource_email, credentials=Credentials(
                self.configuration.email, self.configuration.password), autodiscover=True, access_type=DELEGATE)
        else:
            ews_url = self.account.protocol.service_endpoint
            ews_auth_type = self.account.protocol.auth_type
            primary_smtp_address = self.account.primary_smtp_address

            # You can now create the Account without autodiscovering, using the cached values:
            config = Configuration(service_endpoint=ews_url, credentials=Credentials(
                self.configuration.email, self.configuration.password), auth_type=ews_auth_type)
            self.account = Account(
                primary_smtp_address=primary_smtp_address,
                config=config, autodiscover=False,
                access_type=DELEGATE,
            )
        return self.account


"""
Store configurations here on startup
"""


class Store:
    def __init__(self):
        self.items = {}
        self.__lock__ = Lock()

    def lock(self):
        if self.locked():
            return

        self.__lock__.acquire()

    def release(self):
        if not self.locked():
            return

        self.__lock__.release()

    def locked(self):
        return self.__lock__.locked()

    def add(self, instance):
        from resources.models import Resource

        self.items.update({
            instance.id: RespaOutlookManager(instance)
        })
        try:
            res = Resource.objects.get(pk=instance.resource.id)
            res.configuration = instance
            res.save()
        except:
            ...

    def get(self, id):
        return self.items.get(id, None)


store = Store()


def ToEWSDateTime(_datetime):
    tz = EWSTimeZone.timezone('Europe/Helsinki')
    time = tz.localize(
        EWSDateTime(
            year=_datetime.year,
            month=_datetime.month,
            day=_datetime.day,
            hour=_datetime.hour,
            minute=_datetime.minute
        )
    )
    return time
