# Generated by Django 3.2.12 on 2022-08-24 20:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('EventsApp', '0064_auto_20220823_1753'),
    ]

    operations = [
        migrations.AddField(
            model_name='orderitems',
            name='purchased',
            field=models.BooleanField(blank=True, null=True),
        ),
    ]
