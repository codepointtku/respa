from django.apps import AppConfig
from django.db.models.signals import post_save, pre_delete
from django.conf import settings

from exchangelib import EWSDateTime, EWSTimeZone, Mailbox, Attendee, CalendarItem

from respa_outlook.manager import RespaOutlookManager, store


from sys import argv


class RespaOutlookConfig(AppConfig):
    name = 'respa_outlook'
    verbose_name = 'Respa Outlook'

    def ready(self):
        from respa_outlook.signals import configuration_delete, configuration_save
        from respa_outlook.models import RespaOutlookConfiguration
        from respa_outlook.polling import Listen

        if settings.USE_RESPA_EXCHANGE:
            for configuration in RespaOutlookConfiguration.objects.all():
                store.items.update({
                    configuration.id: RespaOutlookManager(configuration)
                })
                if store.items.get(configuration.id).pop_from_store:      # Remove failed managers
                    store.items.pop(configuration.id)
            Listen(store)
        post_save.connect(
            configuration_save,
            sender=RespaOutlookConfiguration,
            dispatch_uid='respa-outlook-config-save'
        )
        pre_delete.connect(
            configuration_delete,
            sender=RespaOutlookConfiguration,
            dispatch_uid='respa-outlook-config-delete'
        )
