from django.conf import settings

from respa_outlook.models import RespaOutlookReservation
from django.core.exceptions import ValidationError

from exchangelib.errors import ErrorItemNotFound, ErrorAccessDenied

from time import sleep, time
from copy import copy

from threading import Thread, Event

import logging

logger = logging.getLogger()


class Listen():
    def __init__(self, store):
        self.store = store
        self.configs = store.items
        self.status = False
        self.creating = False
        self.modifying = False
        self.thread = Thread(target=self.start)
        self.signal = Event()
        self.manager = None
        self.config = None
        self.calendar = None
        self.thread.setDaemon(True)
        self.thread.start()

    def start(self):
        while not self.signal.wait(0):
            pop = []

            configs = copy(self.configs)  # Avoid RunTimeError this way

            for manager in configs:
                self.manager = self.configs[manager]
                if self.manager.pop_from_store:
                    pop.append(self.manager)
                    continue

                self.config = self.manager.configuration
                self.calendar = copy(self.manager.future())

                assert self.manager is not None
                assert self.config is not None
                assert self.calendar is not None

                try:
                    self.handle_add()
                    self.manager.failed = False
                    self.manager.reported = False
                except ErrorAccessDenied:
                    if not self.manager.reported:
                        logger.warning("Configuration email: \"%(config_email)s\" does not have the permission to access resource \"%(resource)s\" email: \"%(resource_email)s\"" % ({
                            'config_email': self.config.email,
                            'resource': self.config.resource.name,
                            'resource_email': self.config.resource.resource_email
                        }))
                        self.manager.reported = True
                    self.manager.failed = True

                self.manager = None
                self.config = None
                self.calendar = None

            for manager in pop:
                self.configs.pop(manager.configuration.id)
            sleep(settings.OUTLOOK_POLLING_RATE)

    def stop(self):
        self.signal.set()

    def handle_add(self):
        for appointment in self.calendar:
            if len(appointment.body.split('respa_fingerprint=')) <= 1:
                continue
            try:
                RespaOutlookReservation.objects.get(exchange_id=appointment.id)
                continue
            except:
                try:
                    email = appointment.organizer.email_address
                    self.config.create_respa_outlook_reservation(
                        appointment=appointment,
                        reservation=None,
                        email=email
                    )
                except Exception as ex:
                    if isinstance(ex, ValidationError):
                        appointment.delete()
                    continue
        self.handle_modify()

    def handle_modify(self):
        for appointment in self.calendar:
            if len(appointment.body.split('respa_fingerprint=')) <= 1:
                continue
            try:
                respa_outlook = RespaOutlookReservation.objects.get(exchange_id=appointment.id)
                reservation = respa_outlook.reservation
                if (appointment.start == reservation.begin and
                        appointment.end == reservation.end):
                    continue
                self.config.handle_modify(reservation, appointment)
            except:
                continue
        self.handle_remove()

    def handle_remove(self):
        for appointment in self.calendar:
            if len(appointment.body.split('respa_fingerprint=')) <= 1:
                continue
            try:
                respa_outlook = RespaOutlookReservation.objects.get(exchange_id=appointment.id)
                reservation = respa_outlook.reservation
                if reservation.state == 'cancelled':
                    appointment.delete()
                    respa_outlook.delete()
            except:
                continue
        for outlook in RespaOutlookReservation.objects.all():
            reservation = outlook.reservation
            try:
                appointment = self.calendar.get(id=outlook.exchange_id)
                if isinstance(appointment, ErrorItemNotFound):
                    reservation.state = 'cancelled'
                    reservation.save()
                    outlook.delete()
            except:
                outlook.reservation.state = 'cancelled'
                reservation.save()
                outlook.delete()
