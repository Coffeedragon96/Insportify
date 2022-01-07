# Generated by Django 3.2.8 on 2022-01-07 05:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('EventsApp', '0042_alter_multistep_position_price'),
    ]

    operations = [
        migrations.AlterField(
            model_name='multistep',
            name='event_date',
            field=models.DateField(null=True, verbose_name='Event Date'),
        ),
        migrations.AlterField(
            model_name='multistep',
            name='min_age',
            field=models.IntegerField(null=True, verbose_name='Minimum Age'),
        ),
    ]
