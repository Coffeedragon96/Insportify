# Generated by Django 3.2.12 on 2022-08-29 23:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('EventsApp', '0069_alter_orderitems_checkout_timer'),
    ]

    operations = [
        migrations.AlterField(
            model_name='orderitems',
            name='checkout_timer',
            field=models.DateTimeField(blank=True),
        ),
    ]
