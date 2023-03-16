# Generated by Django 3.2.12 on 2023-03-10 20:46

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('EventsApp', '0002_alter_advertisement_image'),
    ]

    operations = [
        migrations.CreateModel(
            name='Ad_HitCount',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user_ip', models.GenericIPAddressField()),
                ('ad', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='EventsApp.advertisement')),
            ],
        ),
    ]