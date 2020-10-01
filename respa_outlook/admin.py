from django.contrib.admin import ModelAdmin, site
from django.forms.widgets import PasswordInput
from django.utils.translation import gettext_lazy as _


from respa_outlook.models import RespaOutlookConfiguration, RespaOutlookReservation


class RespaOutlookConfigurationAdmin(ModelAdmin):
    list_display = ('name', 'email', 'resource', 'resource_email')
    search_fields = ('name', 'email', 'resource')

    def get_form(self, request, obj=None, **kwargs):  # pragma: no cover
        form = super(RespaOutlookConfigurationAdmin, self).get_form(request, obj, **kwargs)
        form.base_fields["password"].widget = PasswordInput(render_value=True)
        return form

    def resource_email(self, obj):
        return obj.resource.resource_email or 'No email provided.'

    class Meta:
        verbose_name = _("Outlook configuration")
        verbose_name_plural = _("Outlook configurations")


class RespaOutlookReservationAdmin(ModelAdmin):
    list_display = ('name', 'reservation',)
    search_fields = ('name', 'reservation',)
    exclude = ('exchange_id', 'exchange_changekey', )

    class Meta:
        verbose_name = _('Outlook reservation')
        verbose_name_plural = _("Outlook reservations")

    def get_actions(self, request):
        actions = super().get_actions(request)
        if 'delete_selected' in actions:
            del actions['delete_selected']
        return actions


site.register(RespaOutlookConfiguration, RespaOutlookConfigurationAdmin)
site.register(RespaOutlookReservation, RespaOutlookReservationAdmin)
