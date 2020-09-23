import logging
from parler.admin import TranslatableAdmin
from parler.forms import TranslatableModelForm
from django.core.exceptions import ValidationError
from django import forms
from django.contrib import admin
from django.contrib.admin import site as admin_site
from .models import NotificationTemplate, NotificationTemplateGroup
from resources.admin.base import PopulateCreatedAndModifiedMixin, CommonExcludeMixin

logger = logging.getLogger(__name__)

class NotificationTemplateForm(TranslatableModelForm):
    def __init__(self, *args, **kwargs):   
        super().__init__(*args, **kwargs)
 

class NotificationGroupForm(forms.ModelForm):
    class Meta:
        model = NotificationTemplateGroup
        fields = ['identifier','name','templates']

    def clean(self):
        # Raise ValidationError if one tries to add a notification template to a group that already contains a template of that type.
        # A template group cannot contain multiples of one type.
        all_new_templates = self.cleaned_data['templates'].values_list('type', flat=True)
        distinct_new_templates = all_new_templates.distinct()
        if all_new_templates.count() != distinct_new_templates.count():
            logger.info("Attempted to add a notification template to template group that already contains a template of that type.")
            raise ValidationError('Template group cannot contain multiple templates of the same type.')


class NotificationGroupAdmin(PopulateCreatedAndModifiedMixin, CommonExcludeMixin,
                            admin.ModelAdmin):
    form = NotificationGroupForm
                    
class NotificationTemplateAdmin(TranslatableAdmin):
    #
    # When attempting to save, validate Jinja templates based on
    # example data. Possible to get an exception if unknown context
    # variables are accessed?
    #
    form = NotificationTemplateForm


admin_site.register(NotificationTemplateGroup, NotificationGroupAdmin)
admin_site.register(NotificationTemplate, NotificationTemplateAdmin)
