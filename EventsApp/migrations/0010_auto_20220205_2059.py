# Generated by Django 3.2.9 on 2022-02-06 01:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('EventsApp', '0009_profile'),
    ]

    operations = [
        migrations.CreateModel(
            name='AuthGroup',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=150, unique=True)),
            ],
            options={
                'db_table': 'auth_group',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='AuthGroupPermissions',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
            ],
            options={
                'db_table': 'auth_group_permissions',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='AuthPermission',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('codename', models.CharField(max_length=100)),
            ],
            options={
                'db_table': 'auth_permission',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='AuthUser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128)),
                ('last_login', models.DateTimeField(blank=True, null=True)),
                ('is_superuser', models.BooleanField()),
                ('username', models.CharField(max_length=150, unique=True)),
                ('first_name', models.CharField(max_length=150)),
                ('last_name', models.CharField(max_length=150)),
                ('email', models.CharField(max_length=254)),
                ('is_staff', models.BooleanField()),
                ('is_active', models.BooleanField()),
                ('date_joined', models.DateTimeField()),
            ],
            options={
                'db_table': 'auth_user',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='AuthUserGroups',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
            ],
            options={
                'db_table': 'auth_user_groups',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='AuthUserUserPermissions',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
            ],
            options={
                'db_table': 'auth_user_user_permissions',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='DjangoAdminLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('action_time', models.DateTimeField()),
                ('object_id', models.TextField(blank=True, null=True)),
                ('object_repr', models.CharField(max_length=200)),
                ('action_flag', models.SmallIntegerField()),
                ('change_message', models.TextField()),
            ],
            options={
                'db_table': 'django_admin_log',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='DjangoContentType',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('app_label', models.CharField(max_length=100)),
                ('model', models.CharField(max_length=100)),
            ],
            options={
                'db_table': 'django_content_type',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='DjangoMigrations',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('app', models.CharField(max_length=255)),
                ('name', models.CharField(max_length=255)),
                ('applied', models.DateTimeField()),
            ],
            options={
                'db_table': 'django_migrations',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='DjangoSession',
            fields=[
                ('session_key', models.CharField(max_length=40, primary_key=True, serialize=False)),
                ('session_data', models.TextField()),
                ('expire_date', models.DateTimeField()),
            ],
            options={
                'db_table': 'django_session',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='EventsappMasterTable',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('event_title', models.CharField(blank=True, max_length=30, null=True)),
                ('description', models.CharField(blank=True, max_length=30, null=True)),
                ('city', models.CharField(blank=True, max_length=30, null=True)),
                ('country', models.CharField(blank=True, max_length=30, null=True)),
                ('datetimes', models.CharField(blank=True, max_length=50, null=True)),
                ('event_type', models.IntegerField(blank=True, null=True)),
                ('max_age', models.IntegerField(blank=True, null=True)),
                ('min_age', models.IntegerField(blank=True, null=True)),
                ('position', models.CharField(blank=True, max_length=30, null=True)),
                ('province', models.CharField(blank=True, max_length=30, null=True)),
                ('skill', models.CharField(blank=True, max_length=30, null=True)),
                ('sport_category', models.CharField(blank=True, max_length=30, null=True)),
                ('sport_type', models.CharField(blank=True, max_length=30, null=True)),
                ('venue', models.CharField(blank=True, max_length=30, null=True)),
                ('no_of_position', models.IntegerField(blank=True, null=True)),
                ('position_cost', models.IntegerField(blank=True, null=True)),
            ],
            options={
                'db_table': 'EventsApp_master_table',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='EventsappProfile',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('bio', models.TextField()),
            ],
            options={
                'db_table': 'EventsApp_profile',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='EventsappTestCity',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(blank=True, max_length=30, null=True)),
            ],
            options={
                'db_table': 'EventsApp_test_city',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='EventsappTestPerson',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(blank=True, max_length=30, null=True)),
                ('birthdate', models.DateField(blank=True, null=True)),
            ],
            options={
                'db_table': 'EventsApp_test_person',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='is_event_type_master',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('etm_id', models.IntegerField()),
                ('etm_category', models.CharField(blank=True, max_length=100, null=True)),
                ('etm_title', models.CharField(blank=True, max_length=100, null=True)),
                ('etm_description', models.CharField(blank=True, max_length=250, null=True)),
                ('etm_isactive', models.CharField(blank=True, max_length=1, null=True)),
                ('etm_created_by', models.IntegerField(blank=True, null=True)),
                ('etm_updated_by', models.IntegerField(blank=True, null=True)),
                ('etm_updated_date', models.DateTimeField(blank=True, null=True)),
            ],
            options={
                'db_table': 'is_event_type_master',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='IsEventsDetails',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ed_id', models.IntegerField()),
                ('ed_fk_em_id', models.IntegerField(blank=True, null=True)),
                ('ed_fk_sc_id', models.IntegerField(blank=True, null=True)),
                ('ed_fk_sm_id', models.IntegerField(blank=True, null=True)),
                ('ed_fk_sp_id', models.IntegerField(blank=True, null=True)),
                ('ed_fk_spc_id', models.IntegerField(blank=True, null=True)),
                ('ed_fk_sports_position_cost', models.DecimalField(blank=True, decimal_places=65535, max_digits=65535, null=True)),
                ('ed_created_date', models.DateTimeField(blank=True, null=True)),
                ('ed_created_by', models.IntegerField(blank=True, null=True)),
                ('ed_updated_by', models.IntegerField(blank=True, null=True)),
                ('ed_updated_date', models.DateTimeField(blank=True, null=True)),
                ('is_active', models.CharField(blank=True, max_length=1, null=True)),
            ],
            options={
                'db_table': 'is_events_details',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='IsEventsMaster',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('em_id', models.IntegerField()),
                ('em_title', models.CharField(blank=True, max_length=100, null=True)),
                ('em_desc', models.CharField(blank=True, max_length=250, null=True)),
                ('em_fk_etm_id', models.IntegerField(blank=True, null=True)),
                ('em_gender', models.CharField(blank=True, max_length=10, null=True)),
                ('em_isactive', models.CharField(blank=True, max_length=1, null=True)),
                ('em_created_date', models.DateTimeField(blank=True, null=True)),
                ('em_created_by', models.IntegerField(blank=True, null=True)),
                ('em_updated_by', models.IntegerField(blank=True, null=True)),
                ('em_updated_date', models.DateTimeField(blank=True, null=True)),
            ],
            options={
                'db_table': 'is_events_master',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='IsEventsNotification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('en_id', models.IntegerField()),
                ('en_fk_em_id', models.IntegerField(blank=True, null=True)),
                ('en_fk_nm_id', models.IntegerField(blank=True, null=True)),
                ('en_created_by', models.IntegerField(blank=True, null=True)),
                ('en_updated_by', models.IntegerField(blank=True, null=True)),
                ('en_updated_date', models.DateTimeField(blank=True, null=True)),
                ('is_active', models.CharField(blank=True, max_length=1, null=True)),
            ],
            options={
                'db_table': 'is_events_notification',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='IsEventsScheduler',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('es_id', models.IntegerField()),
                ('es_fk_em_id', models.IntegerField(blank=True, null=True)),
                ('es_from_date', models.DateTimeField(blank=True, null=True)),
                ('es_to_date', models.DateTimeField(blank=True, null=True)),
                ('es_venue_name', models.CharField(blank=True, max_length=100, null=True)),
                ('es_event_venue_street', models.CharField(blank=True, max_length=100, null=True)),
                ('es_event_venue_city', models.CharField(blank=True, max_length=50, null=True)),
                ('es_event_venue_province', models.CharField(blank=True, max_length=50, null=True)),
                ('es_event_venue_country', models.CharField(blank=True, max_length=100, null=True)),
                ('es_event_venue_zip', models.CharField(blank=True, max_length=6, null=True)),
                ('em_fk_etm_id', models.IntegerField(blank=True, null=True)),
                ('es_fk_ef_id', models.IntegerField(blank=True, null=True)),
                ('es_min_age', models.DecimalField(blank=True, decimal_places=65535, max_digits=65535, null=True)),
                ('es_max_age', models.DecimalField(blank=True, decimal_places=65535, max_digits=65535, null=True)),
                ('em_isactive', models.CharField(blank=True, max_length=1, null=True)),
                ('es_created_date', models.DateTimeField(blank=True, null=True)),
                ('es_created_by', models.IntegerField(blank=True, null=True)),
                ('es_updated_by', models.IntegerField(blank=True, null=True)),
                ('es_updated_date', models.DateTimeField(blank=True, null=True)),
            ],
            options={
                'db_table': 'is_events_scheduler',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='IsNotificationMaster',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('nm_id', models.IntegerField()),
                ('nm_title', models.CharField(blank=True, max_length=100, null=True)),
                ('nm_description', models.CharField(blank=True, max_length=250, null=True)),
                ('nm_trigger', models.CharField(blank=True, max_length=10, null=True)),
                ('nm_trigger_frequency', models.CharField(blank=True, max_length=10, null=True)),
                ('nm_isactive', models.CharField(blank=True, max_length=1, null=True)),
                ('nm_created_by', models.IntegerField(blank=True, null=True)),
                ('nm_updated_by', models.IntegerField(blank=True, null=True)),
                ('nm_updated_date', models.DateTimeField(blank=True, null=True)),
            ],
            options={
                'db_table': 'is_notification_master',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='IsSportsCategory',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('sc_id', models.IntegerField()),
                ('sc_sports_catgeory', models.CharField(max_length=100)),
                ('sc_created_by', models.IntegerField(blank=True, null=True)),
                ('sc_created_date', models.DateTimeField(blank=True, null=True)),
                ('sc_updated_by', models.IntegerField(blank=True, null=True)),
                ('sc_updated_date', models.DateTimeField(blank=True, null=True)),
                ('is_active', models.CharField(blank=True, max_length=1, null=True)),
            ],
            options={
                'db_table': 'is_sports_category',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='IsSportsDetails',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('sd_id', models.IntegerField()),
                ('sd_fk_sc_id', models.IntegerField(blank=True, null=True)),
                ('sd_fk_sm_id', models.IntegerField(blank=True, null=True)),
                ('sd_fk_sp_id', models.IntegerField(blank=True, null=True)),
                ('sd_created_by', models.IntegerField(blank=True, null=True)),
                ('sd_created_date', models.DateTimeField(blank=True, null=True)),
                ('sd_updated_by', models.IntegerField(blank=True, null=True)),
                ('sd_updated_date', models.DateTimeField(blank=True, null=True)),
                ('is_active', models.CharField(blank=True, max_length=1, null=True)),
            ],
            options={
                'db_table': 'is_sports_details',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='IsSportsMaster',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('sm_id', models.IntegerField()),
                ('sm_sports_name', models.CharField(max_length=100)),
                ('sm_created_by', models.IntegerField(blank=True, null=True)),
                ('sm_created_date', models.DateTimeField(blank=True, null=True)),
                ('sm_updated_by', models.IntegerField(blank=True, null=True)),
                ('sm_updated_date', models.DateTimeField(blank=True, null=True)),
                ('is_active', models.CharField(blank=True, max_length=1, null=True)),
                ('sm_fk_sc_id', models.IntegerField(blank=True, null=True)),
            ],
            options={
                'db_table': 'is_sports_master',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='IsSportsPosition',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('sp_id', models.IntegerField()),
                ('sp_fk_sc_id', models.IntegerField(blank=True, null=True)),
                ('sp_position_name', models.CharField(max_length=100)),
                ('sp_created_by', models.IntegerField(blank=True, null=True)),
                ('sp_created_date', models.DateTimeField(blank=True, null=True)),
                ('sp_updated_by', models.IntegerField(blank=True, null=True)),
                ('sp_updated_date', models.DateTimeField(blank=True, null=True)),
                ('is_active', models.CharField(blank=True, max_length=1, null=True)),
            ],
            options={
                'db_table': 'is_sports_position',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='IsSportsProficiency',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('spc_id', models.IntegerField()),
                ('spc_prof_name', models.CharField(blank=True, max_length=100, null=True)),
                ('spc_created_date', models.DateTimeField(blank=True, null=True)),
                ('spc_updated_by', models.IntegerField(blank=True, null=True)),
                ('spc_updated_date', models.DateTimeField(blank=True, null=True)),
                ('is_active', models.CharField(blank=True, max_length=1, null=True)),
            ],
            options={
                'db_table': 'is_sports_proficiency',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='IsVenueMaster',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('vm_id', models.IntegerField()),
                ('vm_name', models.CharField(blank=True, max_length=100, null=True)),
                ('vm_venue_description', models.CharField(blank=True, max_length=250, null=True)),
                ('vm_venue_street', models.CharField(blank=True, max_length=250, null=True)),
                ('vm_venuecity', models.CharField(blank=True, max_length=50, null=True)),
                ('vm_venue_province', models.CharField(blank=True, max_length=50, null=True)),
                ('vm_venue_country', models.CharField(blank=True, max_length=50, null=True)),
                ('vm_venue_zip', models.CharField(blank=True, max_length=6, null=True)),
                ('vm_isactive', models.CharField(blank=True, max_length=1, null=True)),
                ('vm_created_by', models.IntegerField(blank=True, null=True)),
                ('vm_updated_by', models.IntegerField(blank=True, null=True)),
                ('vm_updated_date', models.DateTimeField(blank=True, null=True)),
                ('venu_name', models.CharField(blank=True, max_length=17, null=True)),
                ('venue_decription', models.CharField(blank=True, max_length=113, null=True)),
                ('venue_city', models.CharField(blank=True, max_length=6, null=True)),
                ('venue_province', models.CharField(blank=True, max_length=2, null=True)),
                ('venue_zip', models.CharField(blank=True, max_length=10, null=True)),
            ],
            options={
                'db_table': 'is_venue_master',
                'managed': False,
            },
        ),
        migrations.DeleteModel(
            name='Profile',
        ),
    ]
