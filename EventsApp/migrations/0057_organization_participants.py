# Generated by Django 3.2.12 on 2022-08-09 00:20

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('EventsApp', '0056_auto_20220808_1603'),
    ]

    operations = [
        migrations.AddField(
            model_name='organization',
            name='participants',
            field=models.CharField(max_length=100, null=True),
        ),
    ]