from django.conf import settings
from django.db import models
import uuid


class Profile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    role = models.CharField(max_length=16, choices=[(x, x) for x in ('admin', 'operator', 'viewer')])
    generation = models.PositiveIntegerField(default=1)
    must_change_password = models.BooleanField(default=True)


class Audit(models.Model):
    at = models.DateTimeField(auto_now_add=True)
    actor = models.CharField(max_length=32)
    action = models.CharField(max_length=32)
    target = models.CharField(max_length=40, default='')
    outcome = models.CharField(max_length=16)
    before = models.JSONField(default=dict)
    after = models.JSONField(default=dict)
    request_id = models.CharField(max_length=32)


class LoginWindow(models.Model):
    key = models.CharField(max_length=64, primary_key=True)
    started = models.FloatField()
    attempts = models.PositiveIntegerField(default=0)


class DevicePolicy(models.Model):
    device = models.CharField(max_length=12, primary_key=True)
    write_enabled = models.BooleanField(default=False)
    version = models.PositiveIntegerField(default=1)


class MissionRecord(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    course = models.CharField(max_length=64)
    lesson = models.CharField(max_length=64)
    mission = models.CharField(max_length=96)
    scope = models.CharField(max_length=16, default='mission')
    notebook = models.JSONField(default=list)
    content_version = models.CharField(max_length=24)
    title = models.CharField(max_length=200)
    input = models.TextField(default='')
    output = models.TextField(default='')
    interpretation = models.TextField(default='')
    status = models.CharField(max_length=12, default='draft')
    revision = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [models.Index(fields=['user','course','lesson','mission'], name='mission_owner_lookup')]
        constraints = [models.UniqueConstraint(fields=['user','course','lesson','mission'], condition=models.Q(scope='livefire'), name='unique_livefire_record')]


class MissionRevision(models.Model):
    record = models.ForeignKey(MissionRecord, on_delete=models.CASCADE, related_name='revisions')
    number = models.PositiveIntegerField()
    snapshot = models.JSONField()
    bytes = models.PositiveIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['record','number'], name='unique_mission_revision')]


class MissionEvidence(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    record = models.ForeignKey(MissionRecord, on_delete=models.CASCADE, related_name='images')
    image = models.BinaryField()
    sha256 = models.CharField(max_length=64)
    bytes = models.PositiveIntegerField()
    width = models.PositiveIntegerField()
    height = models.PositiveIntegerField()
    caption = models.CharField(max_length=200, default='')
    created_at = models.DateTimeField(auto_now_add=True)
