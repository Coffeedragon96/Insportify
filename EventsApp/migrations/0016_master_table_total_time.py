# Generated by Django 3.2.12 on 2024-11-18 18:20

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('EventsApp', '0015_individual_school'),
    ]

    operations = [
        migrations.AddField(
            model_name='master_table',
            name='total_time',
            field=models.IntegerField(blank=True, null=True),
        ),
    ]
