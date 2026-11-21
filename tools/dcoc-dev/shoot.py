"""개발 서버 화면을 Playwright(msedge)로 찍는다.

    python tools/dcoc-dev/shoot.py <이름> <해시> [--size 1920x1080] [--js "<페이지에서 실행할 식>"]
                                    [--click "<선택자>"]... [--wait 2.5] [--full] [--role admin]

결과: tools/dcoc-dev/shots/<이름>-<너비>.png, 브라우저 콘솔 오류는 표준 출력으로 알린다.
"""
import argparse
import asyncio
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent


async def main() -> int:
    from playwright.async_api import async_playwright
    p = argparse.ArgumentParser()
    p.add_argument("name")
    p.add_argument("hash")
    p.add_argument("--size", default="1920x1080")
    p.add_argument("--js", action="append", default=[])
    p.add_argument("--click", action="append", default=[])
    p.add_argument("--wait", type=float, default=2.5)
    p.add_argument("--full", action="store_true")
    p.add_argument("--role")
    p.add_argument("--base", default="http://127.0.0.1:8765")
    p.add_argument("--motion", default="reduce", help="reduce: 애니메이션 없이 찍는다(기본), no-preference")
    a = p.parse_args()
    if a.role:
        urllib.request.urlopen(f"{a.base}/dev?role={a.role}").read()
    w, h = (int(x) for x in a.size.split("x"))
    out = HERE / "shots"
    out.mkdir(exist_ok=True)
    errors = []
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(channel="msedge", headless=True)
        ctx = await browser.new_context(viewport={"width": w, "height": h}, locale="ko-KR", reduced_motion=a.motion)
        page = await ctx.new_page()
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
        page.on("pageerror", lambda e: errors.append(str(e)))
        await page.goto(f"{a.base}/core/#{a.hash}")
        await page.wait_for_timeout(int(a.wait * 1000))
        for sel in a.click:
            if sel.startswith("wait:"):
                await page.wait_for_timeout(int(float(sel[5:]) * 1000))
                continue
            await page.locator(sel).first.click()
            await page.wait_for_timeout(900)
        for js in a.js:
            r = await page.evaluate(js)
            if r is not None:
                print("js:", r)
            await page.wait_for_timeout(700)
        path = out / f"{a.name}-{w}.png"
        await page.screenshot(path=str(path), full_page=a.full)
        await browser.close()
    print(path)
    for e in errors:
        print("console error:", e)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
