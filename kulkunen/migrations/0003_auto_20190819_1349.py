# Generated by Django 2.1.11 on 2019-08-19 10:49

import django.contrib.postgres.fields.jsonb
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('kulkunen', '0002_add_install_at_and_remove_at'),
    ]

    operations = [
        migrations.AlterField(
            model_name='accesscontrolsystem',
            name='driver_config',
            field=django.contrib.postgres.fields.jsonb.JSONField(blank=True, help_text='Driver-specific configuration', null=True),
        ),
    ]
