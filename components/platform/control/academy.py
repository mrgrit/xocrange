"""Free bundle reader and owner-scoped mission records. Nothing executes input."""
import base64
import hashlib
import io
import json
from pathlib import Path
import re
import warnings
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Sum
from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_GET, require_POST
from .models import MissionRecord, MissionRevision, MissionEvidence
from .security import protected, audit
from .views import data, safe_errors
from .workspace import registry


class Missing(Exception): pass


def boundary(function):
    def wrapped(*args, **kwargs):
        try:
            if not any(c['id']=='academy-reader' for c in registry()['components']):
                return JsonResponse({'error':'component_not_installed'},status=404)
            return function(*args, **kwargs)
        except Missing:
            return JsonResponse({'error':'not_found'},status=404)
        except (OSError, ValueError, KeyError, TypeError):
            return JsonResponse({'error':'content_unavailable'},status=503)
    return wrapped


def content_root():
    return Path(getattr(settings,'ACADEMY_DIR','/run/xoc-platform/academy'))


def read(path):
    if any(p.is_symlink() for p in (path,*path.parents)): raise Missing()
    with path.open('rb') as f: raw=f.read(1048577)
    if len(raw)>1048576: raise ValueError()
    return json.loads(raw)


def course(cid):
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,63}',cid): raise Missing()
    path=content_root()/cid/'course.json'
    if not path.is_file(): raise Missing()
    c=read(path)
    # Paid packages are supplied by the commercial provider with C7 purchase
    # checks; changing a local tier label cannot enable execution in this reader.
    if c['commercial'] is not False or c['minimum_tier']!='community': raise Missing()
    return c


def lesson(cid,lid):
    c=course(cid)
    if lid not in {l['id'] for l in c['lessons']}: raise Missing()
    base=content_root()/cid/'lessons'/lid
    return c,read(base/'lesson.json'),read(base/'missions.json')


def summary(record):
    return {k:str(getattr(record,k)) if k in ('id',) else getattr(record,k) for k in
            ('id','course','lesson','mission','title','content_version','status','revision','created_at','updated_at')}


def image_summary(image):
    return {'id':str(image.id),'url':'/core/api/academy/images/'+str(image.id),'caption':image.caption,
            'width':image.width,'height':image.height,'sha256':image.sha256,'bytes':image.bytes}


def detail(record):
    return summary(record)|{k:getattr(record,k) for k in ('input','output','interpretation')}|{
        'images':[image_summary(i) for i in record.images.defer('image').order_by('created_at')],
        'versions':[{'number':r.number,'at':r.created_at} for r in record.revisions.order_by('-number')],
        'evaluation':{'mode':'self-record','ai_available':False,'minimum_tier':'live-fire'}}


def owned(request,rid):
    r=MissionRecord.objects.filter(id=rid,user=request.user).first()
    if r is None: raise Missing()
    return r


@require_GET
@protected('content.read')
@boundary
def catalog(request):
    result=[]
    for path in sorted(content_root().glob('*/course.json')):
        try:c=course(path.parent.name)
        except Missing:continue
        rows=MissionRecord.objects.filter(user=request.user,course=c['id'])
        result.append({k:c[k] for k in ('id','version','title','subtitle','description','author','review_status','public_pages')}|{
            'lessons':len(c['lessons']),'missions':sum(l['missions'] for l in c['lessons']),
            'completed':rows.filter(status='complete').values('mission').distinct().count(), 'records':rows.count()})
    return JsonResponse({'courses':result,'history_count':MissionRecord.objects.filter(user=request.user).count()})


@require_GET
@protected('content.read')
@boundary
def course_view(request,cid):
    c=course(cid); done=MissionRecord.objects.filter(user=request.user,course=cid,status='complete')
    return JsonResponse({k:c[k] for k in ('id','title','subtitle','version','description','public_pages','review_status')}|{
        'lessons':[l|{'completed':done.filter(lesson=l['id']).values('mission').distinct().count()} for l in c['lessons']]})


@require_GET
@protected('content.read')
@boundary
def lesson_view(request,cid,lid):
    c,l,missions=lesson(cid,lid)
    records=[]
    for m in missions:
        r=MissionRecord.objects.filter(user=request.user,course=cid,lesson=lid,mission=m['id']).order_by('-updated_at').first()
        if r:records.append(detail(r))
    return JsonResponse(l|{'course_id':cid,'course_title':c['title'],'content_version':c['version'],'missions':missions,
        'explanation':read(content_root()/cid/'lessons'/lid/'explanation.json'),'records':records})


@require_GET
@protected('content.read')
@boundary
def asset(request,cid,name):
    c=course(cid)
    if not re.fullmatch(r'[0-9a-f]{64}\.png',name) or name not in c['assets']:raise Missing()
    path=content_root()/cid/'assets'/name
    if path.is_symlink():raise Missing()
    return HttpResponse(path.read_bytes(),content_type='image/png')


def record_snapshot(r):
    value={k:getattr(r,k) for k in ('input','output','interpretation','status')}
    value['images']=[str(v) for v in r.images.values_list('id',flat=True)]
    size=len(json.dumps(value,ensure_ascii=False).encode())
    total=MissionRevision.objects.filter(record__user=r.user).aggregate(n=Sum('bytes'))['n'] or 0
    if total+size>64*1024**2 or r.revision>200:raise ValidationError('record_quota')
    MissionRevision.objects.create(record=r,number=r.revision,snapshot=value,bytes=size)


@protected('content.read')
@safe_errors
@boundary
def record(request,rid=None):
    if request.method=='GET':
        if rid is None:raise Missing()
        return JsonResponse(detail(owned(request,rid)))
    value=data(request,('course','lesson','mission','input','output','interpretation','status','revision'))
    if type(value['revision']) is not int or value['revision']<0 or value['status'] not in ('draft','complete'):raise ValidationError("invalid_input")
    for key in ('course','lesson','mission','input','output','interpretation'):
        if not isinstance(value[key],str) or len(value[key].encode())>24000 or '\x00' in value[key]:raise ValidationError("invalid_input")
    c,l,missions=lesson(value['course'],value['lesson'])
    m=next((m for m in missions if m['id']==value['mission']),None)
    if m is None:raise Missing()
    with transaction.atomic():
        if rid is None:
            if value['revision']!=0:raise ValidationError("invalid_input")
            if MissionRecord.objects.filter(user=request.user).count()>=2000:raise ValidationError('record_quota')
            r=MissionRecord(user=request.user,course=c['id'],lesson=l['id'],mission=m['id'],content_version=c['version'],title=l['title']+' · '+m['title'])
        else:
            r=owned(request,rid)
            if any(value[k]!=getattr(r,k) for k in ('course','lesson','mission')):raise Missing()
            if r.revision!=value['revision']:return JsonResponse({'error':'stale_version'},status=409)
            r.revision+=1
        if value['status']=='complete' and (not value['input'].strip() or not value['interpretation'].strip() or (not value['output'].strip() and (rid is None or not r.images.exists()))):
            return JsonResponse({'error':'mission_incomplete','detail':'입력, 결과 텍스트 또는 캡처, 나의 해석을 모두 기록해 주세요.'},status=400)
        for k in ('input','output','interpretation','status'):setattr(r,k,value[k])
        r.save();record_snapshot(r)
        audit(request,'mission_save','allowed',str(r.id),after={'revision':r.revision,'status':r.status})
    return JsonResponse(detail(r),status=201 if rid is None else 200)


@require_GET
@protected('content.read')
@boundary
def history(request,page=1):
    if not 1<=page<=100:raise Missing()
    rows=MissionRecord.objects.filter(user=request.user).order_by('-updated_at','id')
    return JsonResponse({'page':page,'count':rows.count(),'records':[summary(r) for r in rows[(page-1)*20:page*20]]})


@require_GET
@protected('content.read')
@boundary
def revision(request,rid,number):
    r=owned(request,rid);v=r.revisions.filter(number=number).first()
    if v is None:raise Missing()
    return JsonResponse({'record':summary(r),'number':number,'at':v.created_at,'snapshot':v.snapshot})


def decode_image(value):
    from PIL import Image, UnidentifiedImageError
    if not isinstance(value,str) or len(value)>710000:raise ValidationError("invalid_input")
    match=re.fullmatch(r'data:image/(?:png|jpeg|webp);base64,([A-Za-z0-9+/=]+)',value)
    if not match:raise ValidationError("invalid_input")
    try:
        raw=base64.b64decode(match[1],validate=True)
        if len(raw)>512*1024:raise ValidationError("invalid_input")
        with warnings.catch_warnings():
            warnings.simplefilter('error',Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(raw),formats=['PNG','JPEG','WEBP']) as im:
                if im.width*im.height>8_000_000 or max(im.size)>6000:raise ValidationError("invalid_input")
                im.load();clean=im.convert('RGB');clean.thumbnail((2400,2400))
                out=io.BytesIO();clean.save(out,format='WEBP',quality=90,method=3)
                encoded=out.getvalue()
                if len(encoded)>1024**2:raise ValidationError("invalid_input")
                return encoded,clean.width,clean.height
    except (OSError,ValueError,UnidentifiedImageError,Image.DecompressionBombError,Image.DecompressionBombWarning) as exc:
        raise ValidationError("invalid_input") from exc


@require_POST
@protected('content.read')
@safe_errors
@boundary
def attach(request,rid):
    # Ownership and metadata are checked before decoding an untrusted image.
    owned(request,rid)
    value=data(request,('image','caption','revision'))
    if type(value['revision']) is not int or not isinstance(value['caption'],str) or len(value['caption'])>200:raise ValidationError("invalid_input")
    raw,width,height=decode_image(value['image'])
    with transaction.atomic():
        r=owned(request,rid)
        if r.revision!=value['revision']:return JsonResponse({'error':'stale_version'},status=409)
        if r.images.count()>=3:raise ValidationError('image_limit')
        used=MissionEvidence.objects.filter(record__user=request.user).aggregate(n=Sum('bytes'))['n'] or 0
        if used+len(raw)>128*1024**2:raise ValidationError('image_quota')
        MissionEvidence.objects.create(record=r,image=raw,sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw),width=width,height=height,caption=value['caption'])
        r.revision+=1;r.save();record_snapshot(r)
        audit(request,'mission_image','allowed',str(r.id),after={'revision':r.revision})
    return JsonResponse(detail(r),status=201)


@require_GET
@protected('content.read')
@boundary
def image(request,iid):
    item=MissionEvidence.objects.filter(id=iid,record__user=request.user).first()
    if item is None:raise Missing()
    response=HttpResponse(bytes(item.image),content_type='image/webp')
    response['Content-Disposition']='inline; filename="evidence.webp"'
    return response
