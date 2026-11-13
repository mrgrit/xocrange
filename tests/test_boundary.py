import json
from pathlib import Path

import yaml

from xocrange.boundary import check

ROOT = Path(__file__).resolve().parents[1]


def test_core_source_has_no_paid_functionality():
    report = check(ROOT)
    assert report['status'] == 'passed', report['findings']
    assert report['files_scanned'] > 100


def component(root, name, files, manifest=None, compose=None):
    directory = root / 'components' / name
    directory.mkdir(parents=True)
    for file, text in files.items():
        (directory / file).write_text(text)
    value = {'id': name, 'commercial': False, 'minimum_tier': 'community', 'build_inputs': list(files)}
    if compose is not None:
        (directory / 'compose.yaml').write_text(yaml.safe_dump(compose))
        value['compose'] = 'compose.yaml'
    value.update(manifest or {})
    (directory / 'component.yaml').write_text(yaml.safe_dump(value))


def reported(report, kind, where):
    return any(f['check'] == kind and f['where'].endswith(where) for f in report['findings'])


def test_each_kind_of_paid_functionality_is_reported(tmp_path):
    component(tmp_path, 'clean', {'app.py': "import re\nre.fullmatch('x', 'x')  # llm-free\n"})
    component(tmp_path, 'paid', {'app.py': 'from anthropic import Anthropic\nimport torch\n',
                                 'ui.js': "import x from 'openai';\n",
                                 'Dockerfile': 'RUN pip install --no-cache-dir vllm==0.9 requests\n',
                                 'urls.py': "urlpatterns=[path('core/api/grading/<int:id>', v)]\n",
                                 'site.conf': '<Location /assessor/>\n</Location>\n',
                                 'requirements.lock': 'langchain-core==1.0 \\\n    --hash=sha256:00\n'},
              manifest={'commercial': True},
              compose={'services': {'llm-worker': {'image': 'example/ollama:1'},
                                    'web': {'gpus': 'all', 'environment': {'OPENAI_API_KEY': 'x'}},
                                    'cam': {'devices': ['/dev/nvidia0']}}})
    (tmp_path / 'requirements.lock').write_text('transformers==4.0\npyyaml==6.0\n')
    inventory = tmp_path / 'inventory.json'
    inventory.write_text(json.dumps({'python_packages': [{'name': 'Sentence_Transformers', 'version': '1'}],
                                     'containers': {'web': {'packages': ['cuda-runtime-12\t12.1', 'bash\t5']}},
                                     'images': {'grader': {'reference': 'xoc-grader'}}}))
    report = check(tmp_path, inventory)
    assert report['status'] == 'failed'
    for expected in [('commercial_component', 'components/paid/component.yaml'), ('dependency', 'transformers'),
                     ('dependency', 'langchain-core'), ('import', 'anthropic'), ('import', 'torch'), ('import', 'openai'),
                     ('installed_package', 'vllm'), ('route', 'core/api/grading/<int:id>'), ('route', '/assessor/'),
                     ('compose_name', 'llm-worker'), ('compose_gpu', 'web'), ('compose_gpu', 'cam'),
                     ('compose_model_credential', 'web'), ('host_python_package', 'Sentence_Transformers'),
                     ('container_package', 'cuda-runtime-12'), ('image_name', 'grader')]:
        assert reported(report, *expected), (expected, report['findings'])
    assert not any('clean' in f['where'] for f in report['findings'])
