# Generated by Django 3.2.12 on 2022-05-31 21:20

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('EventsApp', '0035_auto_20220531_1015'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='eventsappmastertable',
            name='position',
        ),
    ]
