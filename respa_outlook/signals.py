from django.dispatch import receiver


from respa_outlook.apps import store
from respa_outlook.manager import RespaOutlookManager
from resources.models import Resource

import logging

logger = logging.getLogger()


def configuration_delete(sender, **kwargs):
    instance = kwargs.get('instance')
    manager = store.items.get(instance.id)
    if manager:
        manager.pop_from_store = True
        logger.info("Removing configuration")


def configuration_save(sender, **kwargs):
    instance = kwargs.get('instance')
    store.add(instance)
    logger.info("Configuration created")
