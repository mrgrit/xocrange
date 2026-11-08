from django.conf import settings
from django.db import models


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
