# Generated by Django 3.2.12 on 2024-10-27 14:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('EventsApp', '0012_extra_loctaions_is_home'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='pronoun',
            options={'ordering': ['id'], 'verbose_name': 'Pronoun', 'verbose_name_plural': 'Pronouns'},
        ),
        migrations.AddField(
            model_name='individual',
            name='medical_info',
            field=models.TextField(blank=True, null=True),
        ),
    ]
