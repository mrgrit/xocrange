from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('control', '0002_academy_mission_records')]
    operations = [
        migrations.AddField(model_name='missionrecord', name='scope', field=models.CharField(default='mission', max_length=16)),
        migrations.AddField(model_name='missionrecord', name='notebook', field=models.JSONField(default=list)),
    ]
