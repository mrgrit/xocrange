"""One authorization gate for every device API, including future K08 handlers."""
from functools import wraps
from django.http import JsonResponse
from .models import Audit, DevicePolicy

ROLES = {'viewer': {'devices.read'}, 'operator': {'devices.read', 'devices.preview'},
         'admin': {'devices.read', 'devices.preview', 'devices.policy', 'users.manage', 'audit.read'}}


def audit(request, action, outcome, target='', before=None, after=None):
    # Callers supply fixed identifiers and an allowlisted state diff, never input bodies.
    Audit.objects.create(actor=request.user.username if request.user.is_authenticated else 'anonymous',
                         action=action, target=target, outcome=outcome, before=before or {}, after=after or {},
                         request_id=request.request_id)


def protected(permission=None):
    def decorate(function):
        @wraps(function)
        def wrapped(request, *args, **kwargs):
            if not request.user.is_authenticated:
                audit(request, 'access', 'denied')
                return JsonResponse({'error': 'authentication_required'}, status=401)
            profile = getattr(request.user, 'profile', None)
            if not profile or request.session.get('generation') != profile.generation:
                request.session.flush()
                return JsonResponse({'error': 'session_revoked'}, status=401)
            if permission and (profile.must_change_password or permission not in ROLES.get(profile.role, set())):
                audit(request, 'authorization', 'denied')
                return JsonResponse({'error': 'permission_denied'}, status=403)
            return function(request, *args, **kwargs)
        return wrapped
    return decorate


def device_permission(request, device, *, write=False):
    """K08 must call this inside its serialized, audited apply transaction."""
    if device not in ('fw', 'ips', 'waf') or not request.user.is_authenticated:
        return False
    profile = getattr(request.user, 'profile', None)
    if not profile or profile.must_change_password or request.session.get('generation') != profile.generation:
        return False
    role = profile.role
    if not write:
        return 'devices.read' in ROLES.get(role, set())
    return role in ('admin', 'operator') and DevicePolicy.objects.get(device=device).write_enabled
