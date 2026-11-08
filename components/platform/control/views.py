import hashlib
import json
import re
import time
from pathlib import Path
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import DatabaseError, IntegrityError, transaction
from django.http import JsonResponse, HttpResponse
from django.middleware.csrf import get_token
from django.views.decorators.http import require_GET, require_POST
from .models import Audit, Profile, DevicePolicy, LoginWindow
from .security import protected, audit


def data(request, required, optional=()):
    try:
        value = json.loads(request.body, object_pairs_hook=unique)
        if not isinstance(value, dict) or not set(required) <= value.keys() or not value.keys() <= set(required) | set(optional):
            raise ValueError()
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise ValidationError('invalid_body')


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def safe_errors(function):
    def call(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except ValidationError:
            return JsonResponse({'error': 'invalid_input'}, status=400)
        except IntegrityError:
            return JsonResponse({'error': 'conflict'}, status=409)
        except DatabaseError:
            return JsonResponse({'error': 'storage_unavailable'}, status=503)
    return call


def password(value, user):
    if not isinstance(value, str) or len(value) > 128:
        raise ValidationError('invalid_password')
    validate_password(value, user)


def csrf_failure(request, reason=''):
    try:
        audit(request, 'csrf', 'denied')
        return JsonResponse({'error': 'csrf_failed'}, status=403)
    except DatabaseError:
        return JsonResponse({'error': 'storage_unavailable'}, status=503)


@require_GET
def page(request):
    return HttpResponse((Path(__file__).parent/'page.html').read_text())


@require_GET
def asset(request, name):
    if name not in ('app.js', 'style.css'):
        return JsonResponse({'error': 'not_found'}, status=404)
    return HttpResponse((Path(__file__).parent/name).read_text(), content_type='text/javascript' if name.endswith('.js') else 'text/css')


@require_GET
def session(request):
    return JsonResponse(session_data(request))


def session_data(request):
    from django.conf import settings
    result = {'csrf_token': get_token(request), 'authenticated': False, 'siem_available': settings.CONFIG.get('siem_available', False), 'consoles': settings.CONFIG.get('consoles', [])}
    if request.user.is_authenticated:
        p = request.user.profile
        if request.session.get('generation') != p.generation:
            request.session.flush()
            return result
        result.update(authenticated=True, username=request.user.username, role=p.role, must_change_password=p.must_change_password)
    return result


@require_POST
@safe_errors
def sign_in(request):
    body = data(request, ['username', 'password'])
    name, secret = body['username'], body['password']
    if not isinstance(name, str) or not re.fullmatch('[a-z][a-z0-9_-]{2,31}', name) or not isinstance(secret, str) or len(secret) > 128:
        raise ValidationError('invalid_login')
    now = time.time()
    # Global and per-account bounded windows; spoofed forwarded IPs do not bypass this.
    with transaction.atomic():
        LoginWindow.objects.filter(started__lt=now-900).delete()
        blocked = False
        for key, limit in [('all', 100), (hashlib.sha256(name.encode()).hexdigest(), 10)]:
            window, _ = LoginWindow.objects.get_or_create(key=key, defaults={'started': now})
            blocked |= window.attempts >= limit
            window.attempts += 1
            window.save()
        if blocked:
            audit(request, 'login', 'rate_limited')
            return JsonResponse({'error': 'try_later'}, status=429)
        user = authenticate(request, username=name, password=secret)
        if user is None or not Profile.objects.filter(user=user).exists():
            audit(request, 'login', 'denied')
            return JsonResponse({'error': 'invalid_credentials'}, status=401)
        login(request, user)
        request.session['authenticated_at'] = now
        request.session['generation'] = user.profile.generation
        audit(request, 'login', 'allowed')
        request.session.save()
    return JsonResponse(session_data(request))


@require_POST
@protected()
@safe_errors
def sign_out(request):
    data(request, [])
    with transaction.atomic():
        audit(request, 'logout', 'allowed')
        logout(request)
    return JsonResponse({'ok': True})


@require_POST
@protected()
@safe_errors
def change_password(request):
    body = data(request, ['current_password', 'password'])
    if not isinstance(body['current_password'], str) or not request.user.check_password(body['current_password']):
        audit(request, 'password', 'denied')
        return JsonResponse({'error': 'invalid_credentials'}, status=403)
    password(body['password'], request.user)
    with transaction.atomic():
        request.user.set_password(body['password'])
        request.user.save()
        p = request.user.profile
        p.must_change_password = False
        p.generation += 1
        p.save()
        update_session_auth_hash(request, request.user)
        request.session['generation'] = p.generation
        audit(request, 'password', 'changed')
        request.session.save()
    return JsonResponse({'ok': True, 'csrf_token': get_token(request)})


@protected('users.manage')
@safe_errors
def users(request):
    if request.method == 'GET':
        return JsonResponse({'users': list(Profile.objects.order_by('user__username').values('user__username', 'role', 'user__is_active', 'generation'))})
    body = data(request, ['username', 'role', 'active'], ['password'])
    name = body['username']
    if not isinstance(name, str) or not re.fullmatch('[a-z][a-z0-9_-]{2,31}', name) or body['role'] not in ('admin','operator','viewer') or type(body['active']) is not bool:
        raise ValidationError('invalid_user')
    if name == request.user.username:
        return JsonResponse({'error': 'self_change_forbidden'}, status=403)
    with transaction.atomic():
        user, created = User.objects.get_or_create(username=name)
        p, _ = Profile.objects.get_or_create(user=user, defaults={'role': body['role']})
        before = {} if created else {'role': p.role, 'active': user.is_active}
        if created and 'password' not in body:
            raise ValidationError('password_required')
        if 'password' in body:
            password(body['password'], user)
            user.set_password(body['password'])
            p.must_change_password = True
        p.role = body['role']
        p.generation += 1
        user.is_active = body['active']
        user.save(); p.save()
        audit(request, 'user', 'changed', name, before, {'role': p.role, 'active': user.is_active})
    return JsonResponse({'ok': True}, status=201 if created else 200)


@require_GET
@protected('audit.read')
def audits(request):
    return JsonResponse({'events': list(Audit.objects.order_by('-id').values()[:100])})


@protected('devices.read')
@safe_errors
def devices(request, device=None):
    if request.method == 'GET':
        if device is not None and device not in ('fw','ips','waf'):
            return JsonResponse({'error': 'not_found'}, status=404)
        items = DevicePolicy.objects.filter(device=device) if device else DevicePolicy.objects.all()
        return JsonResponse({'devices': list(items.values()), 'configuration_api': 'console_v1'})
    return policy(request, device)


@protected('devices.policy')
def policy(request, device):
    if device not in ('fw','ips','waf'):
        return JsonResponse({'error': 'not_found'}, status=404)
    body = data(request, ['write_enabled', 'version'])
    if type(body['write_enabled']) is not bool or type(body['version']) is not int:
        raise ValidationError('invalid_policy')
    with transaction.atomic():
        p = DevicePolicy.objects.get(device=device)
        if p.version != body['version']:
            return JsonResponse({'error': 'stale_version'}, status=409)
        before = {'write_enabled': p.write_enabled, 'version': p.version}
        p.write_enabled = body['write_enabled']; p.version += 1; p.save()
        audit(request, 'device_policy', 'changed', device, before, {'write_enabled': p.write_enabled, 'version': p.version})
    return JsonResponse({'ok': True, 'version': p.version})
