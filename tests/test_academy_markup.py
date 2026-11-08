import json
from pathlib import Path
import shutil
import subprocess
import pytest


@pytest.mark.skipif(not shutil.which('node'),reason='Node is needed for the browser renderer test')
def test_lesson_markdown_is_structural_html_and_never_executable():
    source=Path(__file__).resolve().parents[1]/'components/platform/control/academy-markup.js'
    code="const fs=require('fs'),vm=require('vm'); const s=fs.readFileSync(process.argv[1],'utf8'); console.log(vm.runInNewContext(s+'; AcademyMarkup.render('+JSON.stringify(fs.readFileSync(0,'utf8'))+')'));"
    text='# 제목\n**강조**와 `rule.id`\n\n1. 첫 단계\n2. 다음 단계\n\n| 필드 | 설명 |\n| --- | --- |\n| `id` | **식별자** |\n\n```bash\ncurl "<script>"\n```\n<script>alert(1)</script>\n[bad](javascript:alert)\n[docs](https://example.com/)'
    html=subprocess.check_output(['node','-e',code,str(source)],input=text,text=True)
    for expected in ('<h3>제목</h3>','<strong>강조</strong>','<code>rule.id</code>','<ol>','<table>','&lt;script&gt;','rel="noopener noreferrer"'):
        assert expected in html
    assert '<script>' not in html and 'href="javascript:' not in html and '**강조**' not in html
    wildcards='wazuh-alerts-* 선택 (아카이브는 wazuh-archives-*)'
    html=subprocess.check_output(['node','-e',code,str(source)],input=wildcards,text=True)
    assert wildcards in html and '<em>' not in html
