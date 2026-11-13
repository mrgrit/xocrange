"""Release boundary check: Core artifacts carry no paid-module functionality.

Paid functionality that must not ship in Core (ADR-0001, CLAUDE.md): Assessor
and grading/battle execution (M15), AI workers, LLM calls, models and GPUs
(M5/M7/M9), and facility/injector simulation (M4). Text search for those words
is useless (``fullmatch`` contains "llm"), so each check reads a structured
source: dependency names, import statements, package inventories, Compose
service definitions and route paths.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

# Distribution names, normalized to lowercase with '-' separators.
PACKAGE = re.compile(r'^(?:openai|anthropic|langchain(?:-.+)?|llama-cpp-python|llama-index(?:-.+)?|ollama|vllm'
                     r'|transformers|torch|torchvision|torchaudio|tensorflow(?:-.+)?|jax|jaxlib|sentence-transformers'
                     r'|huggingface-hub|tiktoken|litellm|google-generativeai|google-genai|mistralai|cohere'
                     r'|onnxruntime-gpu|xformers|accelerate|bitsandbytes|nvidia-.+|cuda-.+|libcudnn.*)$')
PY_IMPORT = re.compile(r'^\s*(?:import|from)\s+(openai|anthropic|langchain\w*|llama_index|ollama|vllm|transformers'
                       r'|torch|tensorflow|jax|litellm|tiktoken|mistralai|cohere|google\.generativeai|google\.genai)\b', re.M)
JS_IMPORT = re.compile(r'''(?:require\(\s*|from\s+|import\s*\(\s*)['"](openai|@anthropic-ai/[\w-]+|langchain[\w/-]*|ollama|@google/generative-ai)['"]''')
INSTALL_LINE = re.compile(r'\b(?:pip3?|npm|yarn|pnpm|apt-get|apk|dnf|yum)\b[^\n]*\binstall\b[^\n]*', re.I)
# Service, image and route names that identify paid functionality.
NAME = re.compile(r'(?:^|[/_.:-])(assessor|grader|grading|scoring|llm|ollama|vllm|ai-?worker|injector|envsim)(?:$|[/_.:-])', re.I)
ROUTE = re.compile(r'(?:^|/)(assessor|grade|grader|grading|score|scoring|llm|injector|envsim|answers?|solutions?)(?:$|/)', re.I)
SECRET_ENV = re.compile(r'^(?:OPENAI|ANTHROPIC|GEMINI|GOOGLE_GENAI|MISTRAL|COHERE|HF|HUGGINGFACE)_[A-Z_]*(?:KEY|TOKEN)$')


def _normalize(name):
    return re.sub(r'[_.]+', '-', name.strip().lower())


def _requirement_names(text):
    for line in text.splitlines():
        line = line.split('#', 1)[0].strip()
        if line and not line.startswith(('-', '--')):
            match = re.match(r'([A-Za-z0-9][A-Za-z0-9._-]*)', line)
            if match:
                yield _normalize(match.group(1))


def _manifests(root):
    for path in sorted((root / 'components').glob('*/component.yaml')):
        yield path, yaml.safe_load(path.read_text())


def _shipped_files(root):
    """Build inputs declared by Core component manifests, plus host runtime code."""
    for path, manifest in _manifests(root):
        for name in manifest.get('build_inputs') or []:
            file = path.parent / name
            if file.is_file():
                yield file
            elif file.is_dir():
                yield from (f for f in file.rglob('*') if f.is_file() and '__pycache__' not in f.parts)
        compose = manifest.get('compose')
        if compose and (path.parent / compose).is_file():
            yield path.parent / compose
    for pattern in ('src/xocrange/**/*.py', 'scripts/*', 'install.sh', 'bin/*'):
        yield from (f for f in root.glob(pattern) if f.is_file() and '__pycache__' not in f.parts)


def _compose_findings(where, document):
    findings = []
    for service, definition in (document or {}).get('services', {}).items():
        definition = definition or {}
        label = f'{where}:{service}'
        if NAME.search(service) or NAME.search(str(definition.get('image', ''))):
            findings.append(('compose_name', label))
        if 'gpus' in definition or definition.get('runtime') == 'nvidia':
            findings.append(('compose_gpu', label))
        devices = ((definition.get('deploy') or {}).get('resources') or {}).get('reservations', {}).get('devices')
        if devices or any('nvidia' in str(d) or '/dev/dri' in str(d) for d in definition.get('devices') or []):
            findings.append(('compose_gpu', label))
        environment = definition.get('environment') or {}
        names = environment if isinstance(environment, dict) else [str(e).split('=', 1)[0] for e in environment]
        if any(SECRET_ENV.match(str(name)) for name in names):
            findings.append(('compose_model_credential', label))
    return findings


def check(root, inventory=None, compose_files=()):
    root = Path(root)
    findings = []
    for path, manifest in _manifests(root):
        if manifest.get('commercial') or manifest.get('minimum_tier', 'community') != 'community':
            findings.append(('commercial_component', str(path.relative_to(root))))
    for lock in [root / 'requirements.lock', *sorted(root.glob('components/*/requirements.lock'))]:
        if lock.is_file():
            findings += [('dependency', f'{lock.relative_to(root)}:{n}') for n in _requirement_names(lock.read_text()) if PACKAGE.match(n)]
    scanned = 0
    for file in sorted(set(_shipped_files(root))):
        try:
            text = file.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        scanned += 1
        relative = str(file.relative_to(root))
        if file.suffix == '.py' or text.startswith('#!/usr/bin/env python'):
            findings += [('import', f'{relative}:{m.group(1)}') for m in PY_IMPORT.finditer(text)]
        if file.suffix in ('.js', '.mjs', '.html'):
            findings += [('import', f'{relative}:{m.group(1)}') for m in JS_IMPORT.finditer(text)]
        for line in INSTALL_LINE.findall(text):
            findings += [('installed_package', f'{relative}:{w}') for w in re.findall(r'[A-Za-z0-9][A-Za-z0-9._-]+', line) if PACKAGE.match(_normalize(w))]
        if file.name.startswith('compose') and file.suffix in ('.yaml', '.yml'):
            findings += _compose_findings(relative, yaml.safe_load(text))
        if file.name == 'urls.py':
            findings += [('route', f'{relative}:{p}') for p in re.findall(r"path\(\s*'([^']*)'", text) if ROUTE.search(p)]
        if file.suffix == '.conf':
            findings += [('route', f'{relative}:{p}') for p in re.findall(r'^\s*(?:ProxyPass|ProxyPassMatch|Alias|<Location(?:Match)?)\s+"?([^\s">]+)', text, re.M) if ROUTE.search(p)]
    for path in compose_files:
        findings += _compose_findings(str(path), yaml.safe_load(Path(path).read_text()))
    if inventory:
        value = json.loads(Path(inventory).read_text())
        findings += [('host_python_package', p['name']) for p in value.get('python_packages', []) if PACKAGE.match(_normalize(p['name']))]
        for service, container in value.get('containers', {}).items():
            for line in container.get('packages', []):
                name = _normalize(line.split('\t', 1)[0])
                if PACKAGE.match(name):
                    findings.append(('container_package', f'{service}:{name}'))
        for service, image in value.get('images', {}).items():
            if NAME.search(service) or NAME.search(image.get('reference', '')):
                findings.append(('image_name', service))
    return {'status': 'failed' if findings else 'passed', 'files_scanned': scanned,
            'findings': [{'check': c, 'where': w} for c, w in findings]}
