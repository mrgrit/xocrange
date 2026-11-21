"""테스트 서버 Core의 읽기 전용 응답을 한 번 저장한다(GET만 보낸다).

저장된 브라우저 세션 도구(xoc_browser.py의 new_context)가 있는 폴더를 XOC_BROWSER_TOOLS 환경 변수로 지정한다.
요청(POST)은 보내지 않는다. 결과는 captured/ 아래에 두며 git에 올리지 않는다.

    XOC_BROWSER_TOOLS=<폴더> python tools/dcoc-dev/capture.py https://<Core 주소>
"""
import asyncio
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
VIDEOS = Path(os.environ.get("XOC_BROWSER_TOOLS", "."))
OUT = HERE / "captured"
PATHS = ["session", "registry", "datacenter", "datacenter/floors/B1", "datacenter/floors/SITE",
         "datacenter/floors/2F", "datacenter/floors/6F", "facility", "academy", "noc", "lab", "license"]


async def main(base: str) -> int:
    sys.path.insert(0, str(VIDEOS))
    from playwright.async_api import async_playwright
    from xoc_browser import new_context
    OUT.mkdir(exist_ok=True)
    async with async_playwright() as p:
        browser = await p.chromium.launch(channel="msedge", headless=True)
        ctx = await new_context(browser)
        ok = 0
        for path in PATHS:
            r = await ctx.request.get(f"{base}/core/api/{path}", fail_on_status_code=False)
            try:
                body = await r.json()
            except Exception:
                body = None
            print(f"{r.status} {path}")
            if r.status == 200 and body is not None:
                (OUT / (path.replace("/", "_") + ".json")).write_text(json.dumps(body, ensure_ascii=False, indent=1), encoding="utf-8")
                ok += 1
        await browser.close()
    return 0 if ok else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("사용법: capture.py https://<Core 주소>")
    sys.exit(asyncio.run(main(sys.argv[1])))
