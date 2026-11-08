#!/usr/bin/env python3
"""Build the owner's approved 1–339 slide bundle; never distribute the PPTX."""
import argparse
import hashlib
import json
from pathlib import Path
import posixpath
import re
import subprocess
import xml.etree.ElementTree as ET
import zipfile

p = argparse.ArgumentParser()
p.add_argument('--pptx', type=Path, required=True)
p.add_argument('--manuscript', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
if a.output.exists(): p.error('Choose a new output directory')
NS = {'p':'http://schemas.openxmlformats.org/presentationml/2006/main',
      'a':'http://schemas.openxmlformats.org/drawingml/2006/main',
      'r':'http://schemas.openxmlformats.org/officeDocument/2006/relationships'}


def adapt(text):
    # Preserve executable token boundaries; prose uses the product display name.
    text = re.sub(r'(?i)kt66\s*검증\s*완료', '원본 교재 검증 기록', text)
    text = re.sub(r'(?i)kt66(?=[-_/.:])', 'xocrange', text)
    return re.sub(r'(?i)kt66', 'xOC Range', text)


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2)+'\n')


def relations(z, part):
    rel = posixpath.join(posixpath.dirname(part), '_rels', posixpath.basename(part)+'.rels')
    if rel not in z.namelist(): return {}
    return {r.get('Id'):posixpath.normpath(posixpath.join(posixpath.dirname(part),r.get('Target')))
            for r in ET.fromstring(z.read(rel)) if r.get('TargetMode') != 'External'}


def plain(node):
    return adapt('\n'.join(''.join(t.text or '' for t in p.findall('.//a:t',NS))
                           for p in node.findall('.//a:p',NS))).strip()


assets = {}; slides = []
with zipfile.ZipFile(a.pptx) as z:
    deck = ET.fromstring(z.read('ppt/presentation.xml')); rels = relations(z,'ppt/presentation.xml')
    ordered = [rels[node.get('{'+NS['r']+'}id')] for node in deck.findall('p:sldIdLst/p:sldId',NS)]
    if len(ordered) < 339: raise ValueError('The approved deck must contain page 339')
    for page, part in enumerate(ordered[:339],1):
        root = ET.fromstring(z.read(part)); media = relations(z,part); blocks = []
        for shape in root.findall('p:cSld/p:spTree/*',NS):
            table = shape.find('.//a:tbl',NS)
            if table is not None:
                blocks.append({'type':'table','rows':[[plain(c) for c in row.findall('a:tc',NS)] for row in table.findall('a:tr',NS)]})
            elif shape.tag.endswith('}pic'):
                blip = shape.find('.//a:blip',NS)
                ref = media.get(blip.get('{'+NS['r']+'}embed')) if blip is not None else None
                if ref and ref.endswith('.png'):
                    raw = z.read(ref)
                    if not raw.startswith(b'\x89PNG\r\n\x1a\n'): raise ValueError('Invalid screenshot')
                    digest = hashlib.sha256(raw).hexdigest(); name = digest+'.png'
                    target = a.output/'assets'/name; target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(raw)
                    assets.setdefault(name, {'sha256':digest,'bytes':len(raw),'source_pages':[]})['source_pages'].append(page)
                    blocks.append({'type':'image','asset':name,'alt':f'교재 {page}페이지 예시 화면'})
            else:
                text = plain(shape)
                if text: blocks.append({'type':'text','text':text})
        title = next((b['text'].splitlines()[0] for b in blocks if b['type']=='text'),f'페이지 {page}')
        slides.append({'page':page,'title':title,'blocks':blocks})

starts = [52,64,75,85,98,107,116,127,138,149,159,167,175,183,192,204,213,222,230,239,249,258,268,278,286,297,305,313,322,330]
topics = ['SQL 인젝션','XSS','디렉터리 트래버설 / LFI','웹 스캐너와 경로 탐색','스캐너 User-Agent','웹 로그인 브루트포스',
          '웹셸 업로드와 실행','Log4Shell','Shellshock','OS 명령 삽입','공격 요청의 200 응답','서버 오류 급증',
          '비정상 HTTP 메서드','관리 페이지 외부 접근','비정상적으로 긴 URL','SSH 브루트포스','없는 계정의 인증 시도',
          '인증 실패 뒤의 성공','root 직접 로그인','sudo 권한 사용','계정·그룹 생성과 삭제','핵심 계정 파일 변경',
          'SSH 키 지속화','cron 지속화','네트워크 도구 실행 흔적','다운로드 후 실행','시스템 바이너리 변경',
          '로그 삭제·변경','새 수신 대기 포트','포트 스캔과 방화벽 드롭']
refs = [(5,5),(5,7),(5,8),(6,2),(6,3),(6,5),(7,2),(7,3),(7,4),(7,5),(7,6),(7,7),(6,3),(6,2),(6,4),
        (8,2),(8,3),(8,4),(8,5),(8,6),(8,7),(9,2),(9,3),(9,4),(9,5),(9,6),(9,7),(9,8),(10,2),(10,3)]
items = [('orientation','학습 흐름과 사건 노트',1,4,'시작하기',(2,7)),
         ('discover','Discover에서 기록 찾기',5,19,'시작하기',(3,2)),
         ('dql','DQL 문법과 검색 필드',20,33,'시작하기',(3,4)),
         ('infrastructure','실습 인프라와 수집 경로',34,46,'시작하기',(4,1)),
         ('web-basics','웹 요청·로그·WAF 기초',47,51,'웹 위협',(5,1))]
for i,(start,title,ref) in enumerate(zip(starts,topics,refs),1):
    if i==16: items.append(('linux-basics','리눅스 인증·권한·로그 기초',200,203,'리눅스 위협',(8,1)))
    end = (starts[i]-1 if i<30 else 339) if i!=15 else 199
    items.append((f'case-{i:02}',f'{i:02} · {title}',start,end,'웹 위협' if i<=15 else '리눅스 위협',ref))

lessons = []; source_map = []
for slug,title,start,end,section,ref in items:
    selected = slides[start-1:end]; folder = a.output/'lessons'/slug
    mission_data = []
    for kind,label,needle,goal in [
        ('execute','입력과 실행','실습 ①','설명에 제시된 절차를 읽고 실습 환경에서 수행한 입력, 반환된 결과, 자신의 해석을 기록하세요.'),
        ('investigate','검색과 증거','실습 ②','검색 대상·시간 범위·DQL 조건을 기록하고, 결과 텍스트나 화면을 근거로 첨부하세요.'),
        ('interpret','분석과 판단','결과 읽는 법','탐지된 사실과 실행 결과를 구분하세요. 시각·출발지·규칙 ID 등 판단에 사용한 근거와 추가 확인할 내용을 적으세요.')]:
        pages = [s['page'] for s in selected if needle in s['title']]
        if not slug.startswith('case-'):
            if kind!='investigate': continue
            goal = '이번 차시에서 확인한 화면·검색식·설정을 직접 기록하세요. 확인 결과와 자신의 해석을 함께 남기세요.'
        mission_data.append({'id':slug+'-'+kind,'title':label,'instruction':goal,'source_pages':pages or [start],
                             'required_fields':['input','output_or_screenshot','interpretation'],'evaluation':'self-record'})
    chapter,index = ref; filename=f'volume01-chapter{chapter:02}.json'
    book = json.loads((a.manuscript/filename).read_text()); excerpt=book['pages'][index]
    # Only the explicitly mapped explanation section; never the entire manuscript.
    explanation = json.loads(adapt(json.dumps(excerpt,ensure_ascii=False)))
    explanation['source']={'file':filename,'section_index':index,'revision':'REV01', 'mapping_status':'pending-review'}
    for block in explanation['blocks']:
        if block['type']!='image': continue
        source_file=a.manuscript.parents[1]/block['path']
        if not source_file.is_file(): raise ValueError('Fetch the mapped manuscript figure: '+block['path'])
        raw=source_file.read_bytes()
        if not raw.startswith(b'\x89PNG\r\n\x1a\n'): raise ValueError('Expected a manuscript PNG')
        digest=hashlib.sha256(raw).hexdigest();name=digest+'.png'
        (a.output/'assets'/name).write_bytes(raw)
        assets.setdefault(name,{'sha256':digest,'bytes':len(raw),'source_pages':[], 'manuscript_file':block['path']})['source_pages'].append(start)
        block['asset']=name
    write(folder/'explanation.json',explanation)
    for mission in mission_data:
        field='input' if mission['id'].endswith('-execute') else 'output' if mission['id'].endswith('-investigate') else 'interpretation'
        mission['response_field']=field
        mission['response_label']={'input': '실습 과정과 실행 기록', 'output': '전체 결과와 캡처 기록', 'interpretation': '분석과 해석 기록'}[field]
        mission['instruction']={'input': '실습에서 사용한 명령과 검색식, 실행 순서와 시행착오를 노트에 기록하세요. 관련 결과와 캡처도 함께 배치할 수 있습니다.', 'output': '실습하며 나온 전체 출력과 로그, 여러 화면의 캡처를 노트에 이어 붙이세요. 각 결과에서 무엇을 확인했는지 설명을 덧붙이세요.', 'interpretation': '관측한 사실과 판단 근거, 원인과 대응 방향을 충분히 기록하세요. 관련 명령, 결과와 캡처를 연결해 분석 과정을 완성하세요.'}[field]
    write(folder/'missions.json',mission_data)
    write(folder/'lesson.json',{'id':slug,'title':title,'source_pages':[start,end],'slides':selected})
    lessons.append({'id':slug,'title':title,'section':section,'source_pages':[start,end],'missions':len(mission_data)})
    source_map.append({'lesson_id':slug,'slides':[start,end],'explanation':explanation['source']})

assert sorted(p for _,_,s,e,_,_ in items for p in range(s,e+1))==list(range(1,340))
course={'schema_version':'xoc.academy/0.1.0','id':'wazuh-threat-hunting','version':'0.3.0','title':'시스템 침투와 SIEM 분석',
        'subtitle':'Wazuh 위협 탐지 · 웹과 리눅스','description':'입력부터 로그 검색, 증거 해석까지. 30개 사례로 보안관제의 흐름을 익힙니다.',
        'author':'전두용','commercial':False,'minimum_tier':'community','review_status':'pending-content-review',
        'public_pages':339,'lessons':lessons,'assets':assets}
write(a.output/'course.json',course)
book_sha=subprocess.check_output(['git','-C',str(a.manuscript),'rev-parse','HEAD'],text=True).strip()
write(a.output/'source-map.json',{'schema_version':'xoc.content-source/0.1.0','approved_slide_range':[1,339],
      'source_deck':'https://docs.google.com/presentation/d/1os-JBFoYF857D_eTOJJw37eFkRlo4kXf/edit',
      'source_pptx_sha256':hashlib.sha256(a.pptx.read_bytes()).hexdigest(),'manuscript_repository':'https://github.com/mrgrit/hack_ir_with_wazuh_book_1',
      'manuscript_commit':book_sha,'manuscript_directory':'manuscript/REV01','lessons':source_map,
      'adaptation':'KT66 product name replaced; screenshots retain their original evidence. Technical/content concordance deferred by owner.',
      'excluded':['original PPTX','slides after 339','speaker notes','unreferenced media','unmapped manuscript sections']})
print(json.dumps({'lessons':len(lessons),'slides':339,'missions':sum(l['missions'] for l in lessons),'assets':len(assets)},ensure_ascii=False))
