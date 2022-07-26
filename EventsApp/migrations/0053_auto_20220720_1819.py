# Generated by Django 3.2.12 on 2022-07-20 22:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('EventsApp', '0052_auto_20220720_1353'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='user',
            options={},
        ),
        migrations.RemoveField(
            model_name='user',
            name='date_joined',
        ),
        migrations.AlterField(
            model_name='user',
            name='is_active',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='user',
            name='is_staff',
            field=models.BooleanField(default=False),
        ),
    ]