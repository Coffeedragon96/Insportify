# Generated by Django 3.2.12 on 2024-11-13 17:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('EventsApp', '0013_auto_20241027_1940'),
    ]

    operations = [
        migrations.CreateModel(
            name='School',
            fields=[
                ('id', models.IntegerField(primary_key=True, serialize=False, unique=True)),
                ('name', models.CharField(max_length=100)),
            ],
            options={
                'verbose_name': 'School',
                'verbose_name_plural': 'Schools',
                'ordering': ['id'],
            },
        ),
    ]