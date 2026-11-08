import secrets
import time
import re
from django.db import DatabaseError, transaction
from django.http import JsonResponse
from .security import audit


class Boundary:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.request_id = secrets.token_hex(16)
        try:
            if request.method not in ('GET', 'POST'):
                return JsonResponse({'error': 'method_not_allowed'}, status=405)
            limit = 16384
            if re.fullmatch(r'/core/api/academy/records(?:/[0-9a-f-]{36})?',request.path): limit=750000
            if re.fullmatch(r'/core/api/academy/records/[0-9a-f-]{36}/images',request.path): limit=750000
            if request.META.get('CONTENT_LENGTH', '0').isdigit() and int(request.META.get('CONTENT_LENGTH', '0')) > limit:
                return JsonResponse({'error': 'body_too_large'}, status=413)
            if request.GET or request.META.get('HTTP_AUTHORIZATION'):
                return JsonResponse({'error': 'unsupported_credentials_or_query'}, status=400)
            if request.user.is_authenticated and time.time() - request.session.get('authenticated_at', 0) >= 28800:
                request.session.flush()
                return JsonResponse({'error': 'session_expired'}, status=401)
            if request.method == 'POST':
                if len(request.body)>limit:
                    return JsonResponse({'error':'body_too_large'},status=413)
                # Login too: same-origin, non-simple JSON, plus Django's CSRF token.
                from django.conf import settings
                if request.headers.get('Origin') not in settings.CSRF_TRUSTED_ORIGINS or request.content_type != 'application/json':
                    audit(request, 'csrf', 'denied')
                    return JsonResponse({'error': 'origin_or_content_type'}, status=403)
                if request.headers.get('Sec-Fetch-Site') not in (None, 'same-origin', 'none'):
                    audit(request, 'csrf', 'denied')
                    return JsonResponse({'error': 'cross_site'}, status=403)
            response = self.get_response(request)
        except DatabaseError:
            # Unavailable audit DB never permits a state change to succeed.
            response = JsonResponse({'error': 'storage_unavailable'}, status=503)
        response['Cache-Control'] = 'no-store'
        response['X-Request-ID'] = request.request_id
        response['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        return response
