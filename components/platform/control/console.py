"""Authenticated device RPC gateway. Only reviewed local Unix sockets are reachable."""
import json
import socket
from django.conf import settings
from django.db import DatabaseError, transaction
from django.http import JsonResponse
from .models import DevicePolicy
from .security import audit, device_permission, protected
from .views import data, safe_errors


def rpc(device, body):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
        client.settimeout(25);client.connect('/run/xoc-console-'+device+'/api.sock')
        client.sendall(json.dumps(body).encode()+b'\n');chunks=bytearray()
        while not chunks.endswith(b'\n'):
            chunk=client.recv(65536)
            if not chunk: raise OSError('Device disconnected')
            chunks.extend(chunk)
            if len(chunks)>2*1024**2: raise OSError('Device response too large')
    return json.loads(chunks)


@protected('devices.read')
@safe_errors
def endpoint(request,device,action='status'):
    if device not in settings.CONFIG.get('consoles',[]) or action not in ('status','preview','apply'):
        return JsonResponse({'error':'console_not_installed'},status=404)
    if (action=='status')!=(request.method=='GET'):
        return JsonResponse({'error':'method_not_allowed'},status=405)
    if action=='status': body={'action':action}
    else:
        body=data(request,['version','payload'] if action=='preview' else ['version','token'])
        if type(body['version']) is not int: return JsonResponse({'error':'invalid_version'},status=400)
        body.update(action=action,actor=request.user.username,request_id=request.request_id)
    audit_incomplete=False
    try:
        if action=='status': result=rpc(device,body)
        else:
            # Serialize with account/policy changes and persist an intent before device mutation.
            # The device also keeps a durable before/after revision and its own operation journal.
            with transaction.atomic():
                permitted=device_permission(request,device,write=action=='apply',preview=action=='preview') and request.user.profile.role in ('admin','operator')
                if not permitted:
                    audit(request,'console_'+action,'denied',device)
                    return JsonResponse({'error':'device_write_locked' if action=='apply' else 'permission_denied'},status=403)
                audit(request,'console_'+action,'requested',device,{'version':body['version']})
            # Recheck under the DB write lock while sending; prevent concurrent policy lock changes.
            with transaction.atomic():
                if not device_permission(request,device,write=action=='apply',preview=action=='preview'):
                    return JsonResponse({'error':'device_write_locked'},status=403)
                result=rpc(device,body)
                # The device has already acted and keeps its own journal; the
                # "requested" row is committed. Losing only the outcome row
                # must not report an applied change as a failure (503).
                try:
                    with transaction.atomic():
                        audit(request,'console_'+action,'applied' if result.get('ok') and action=='apply' else 'validated' if result.get('ok') else 'rejected',device,
                              {'version':body['version']},{'version':result.get('data',{}).get('version',body['version'])})
                except DatabaseError:
                    audit_incomplete=True
        if not result.get('ok'):
            return JsonResponse({'error':'device_rejected','detail':result.get('error','Operation rejected')},status=result.get('status',503))
        result=result['data']
        if audit_incomplete:
            result=dict(result,audit='incomplete')
        if action=='status':
            result['write_enabled']=device_permission(request,device,write=True)
            result['can_preview']=request.user.profile.role in ('admin','operator')
        return JsonResponse(result)
    except (OSError,ValueError):
        return JsonResponse({'error':'device_unavailable'},status=503)
