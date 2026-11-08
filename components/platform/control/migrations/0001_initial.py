import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Audit',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('at', models.DateTimeField(auto_now_add=True)),
                ('actor', models.CharField(max_length=32)),
                ('action', models.CharField(max_length=32)),
                ('target', models.CharField(default='', max_length=40)),
                ('outcome', models.CharField(max_length=16)),
                ('before', models.JSONField(default=dict)),
                ('after', models.JSONField(default=dict)),
                ('request_id', models.CharField(max_length=32)),
            ],
        ),
        migrations.CreateModel(
            name='DevicePolicy',
            fields=[
                ('device', models.CharField(max_length=12, primary_key=True, serialize=False)),
                ('write_enabled', models.BooleanField(default=False)),
                ('version', models.PositiveIntegerField(default=1)),
            ],
        ),
        migrations.CreateModel(
            name='LoginWindow',
            fields=[
                ('key', models.CharField(max_length=64, primary_key=True, serialize=False)),
                ('started', models.FloatField()),
                ('attempts', models.PositiveIntegerField(default=0)),
            ],
        ),
        migrations.CreateModel(
            name='Profile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('role', models.CharField(choices=[('admin', 'admin'), ('operator', 'operator'), ('viewer', 'viewer')], max_length=16)),
                ('generation', models.PositiveIntegerField(default=1)),
                ('must_change_password', models.BooleanField(default=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
