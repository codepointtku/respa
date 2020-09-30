from exchangelib import Account, Credentials, EWSDateTime, EWSTimeZone, IMPERSONATION, DELEGATE, Configuration
from exchangelib.errors import ErrorSchemaValidation, ErrorImpersonateUserDenied
from datetime import datetime, timedelta
from time import sleep

from threading import Lock


class RespaOutlookManager:
    def __init__(self, configuration):
        self.configuration = configuration
        self.account = None
        self.pop_from_store = False
        try:
            self.account = self._get_account()
            self.calendar = self.account.calendar
        except ErrorImpersonateUserDenied:
            print("Email: %s does not have the permission to impersonate resource email: %s" %
                  (self.configuration.email, self.configuration.resource.resource_email))
            self.pop_from_store = True

    def future(self):
        return self.account.calendar.filter(end__gte=ToEWSDateTime(datetime.now().replace(microsecond=0)))

    def _get_account(self):
        resource = self.configuration.resource
        if not self.account:
            self.account = Account(primary_smtp_address=resource.resource_email or self.configuration.email, credentials=Credentials(
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
        res = Resource.objects.get(pk=instance.resource.id)
        if res:
            res.configuration = instance
        res.save()


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
