# Generated by Django 3.2.12 on 2024-11-18 18:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('EventsApp', '0016_master_table_total_time'),
    ]

    operations = [
        migrations.AlterField(
            model_name='master_table',
            name='total_time',
            field=models.FloatField(blank=True, null=True),
        ),
    ]