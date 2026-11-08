from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('control', '0003_lesson_notebooks')]
    operations = [migrations.AddConstraint(
        model_name='missionrecord',
        constraint=models.UniqueConstraint(fields=['user','course','lesson','mission'], condition=models.Q(scope='livefire'), name='unique_livefire_record'),
    )]
