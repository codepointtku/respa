from django.core.management.base import BaseCommand, CommandError
from resources.models.reservation import ReservationReminder

from time import time


class Command(BaseCommand):
    help = "Handles email notification reminders."

    def handle(self, *args, **options):
        if not ReservationReminder.objects.all():
            print('No reminders.')
            return
        for reminder in ReservationReminder.objects.all():
            if reminder.reservation.state == 'cancelled':
                reminder.delete()
            elif reminder.reservation.state == 'confirmed':
                if int(time()) > reminder.get_unix_timestamp():
                    reminder.remind()
                    reminder.delete()

