"""개발 서버에서 한 흐름을 실제로 눌러 보고 화면을 찍는다(기능 점검 겸 스크린샷).

    python tools/dcoc-dev/walkthrough.py [--size 1920x1080] [--base http://127.0.0.1:8765]

흐름: 관제 지도 → DCOC → 훈련 갤러리 → 브리핑 → 훈련 시작 → 경보 반영 → 설비 클릭 → 조치 → 진행 막대
      → 해결 확인 → 기록·SIEM 버튼 → 강사 도구 → 강사 숨김 장애(원인 비공개) → 조회자 권한(조작 버튼 없음)
결과: tools/dcoc-dev/shots/wt-<단계>-<너비>.png, 점검 결과는 표준 출력에 PASS/FAIL로 남긴다.
"""
import argparse
import asyncio
import json
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHECKS = []


def check(name, ok, detail=""):
    CHECKS.append((name, bool(ok)))
    print(("PASS " if ok else "FAIL ") + name + (f" — {detail}" if detail else ""), flush=True)


async def main() -> int:
    from playwright.async_api import async_playwright
    p = argparse.ArgumentParser()
    p.add_argument("--size", default="1920x1080")
    p.add_argument("--base", default="http://127.0.0.1:8765")
    p.add_argument("--drill", default="fac05b")
    a = p.parse_args()
    w, h = (int(x) for x in a.size.split("x"))
    out = HERE / "shots"
    out.mkdir(exist_ok=True)
    dev = lambda q: urllib.request.urlopen(f"{a.base}/dev?{q}").read()
    dev("role=admin&license=active")
    errors = []
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(channel="msedge", headless=True)
        ctx = await browser.new_context(viewport={"width": w, "height": h}, locale="ko-KR")
        await ctx.add_init_script("try{localStorage.removeItem('xoc-dcoc-guide')}catch{}")
        page = await ctx.new_page()
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" and "404" not in m.text else None)
        shot = lambda name, full=False: page.screenshot(path=str(out / f"wt-{name}-{w}.png"), full_page=full)
        req = lambda body: page.evaluate("b=>api('facility/requests',b)", body)
        state = lambda: page.evaluate("()=>api('facility').then(d=>d.state)")

        # 깨끗한 출발: 남은 장애·훈련 정리, 배속 1
        await page.goto(f"{a.base}/core/#datacenter")
        await page.wait_for_timeout(2500)
        await req({"action": "clear_all"})
        await req({"action": "time_scale", "value": 1})
        await page.wait_for_timeout(2500)

        # 1. 관제 지도(평상시)
        await page.reload()
        await page.wait_for_timeout(6000)
        check("지도: 설비에 실시간 상태가 입혀짐", await page.locator(".dc-world .fc-live").count() > 20)
        check("지도: 머리줄 실시간 요약", await page.locator("#dc-live .dc-live-chip").count() >= 3)
        await shot("map-normal")

        # 2. DCOC 첫 화면 + 안내
        await page.goto(f"{a.base}/core/#module/m4-facility")
        await page.wait_for_timeout(4000)
        for sel in ["#facility-scale", ".facility-summary", ".facility-aisles", "[data-panel=summary]", "[data-panel=power-chain]",
                    "[data-panel=cooling-chain]", "[data-panel=aisles]", "[data-panel=assets]", "[data-panel=cluster]", "[data-panel=alarms]",
                    "[data-panel=events]", "[data-panel=instructor]", "[data-panel=work]", "[data-panel=operate]"]:
            check("선택자 " + sel, await page.locator(sel).count() >= 1)
        check("관리자는 강사 도구가 펼쳐져 있음", await page.locator("#facility-fault").is_visible())
        for sel in ["#facility-target", "#facility-minutes", "[data-facility=inject]"]:
            check("선택자 " + sel, await page.locator(sel).count() == 1)
        await shot("dcoc-top")

        # 3. 훈련 갤러리 → 브리핑 → 시작
        await page.locator("[data-action=drill-open]").first.click()
        await page.wait_for_timeout(800)
        check("갤러리: 훈련 카드", await page.locator(".fc-card[data-drill]").count() >= 10)
        await shot("gallery")
        await page.locator(f".fc-card[data-drill={a.drill}]").click()
        await page.wait_for_timeout(600)
        await shot("brief")
        await page.locator("[data-action=drill-start]").click()
        await page.wait_for_timeout(5000)
        s = await state()
        check("훈련 시작이 시뮬레이터에 반영됨", s["drill"] and s["drill"]["status"] == "running")
        check("훈련 배너", await page.locator("[data-panel=drill][data-drill-kind=scenario]").count() >= 1)
        check("훈련 중 원인 비공개(장애 목록에 훈련 장애가 없음)", all(f["fault"] == "hidden" or f["requested_by"] != "훈련 시나리오" for f in s["faults"]))
        await page.select_option("#facility-scale", "10")
        await page.wait_for_timeout(20000)
        s = await state()
        check("경보 발생", len(s["alarms"]) > 0, f"{len(s['alarms'])}건")
        await shot("dcoc-drill")

        # 4. 설비 클릭 → 인스펙터 → 조치
        bad = next((x for x in s["assets"] if x["status"] == "critical"), None) or next(x for x in s["assets"] if x["status"] == "warning")
        await page.locator(f"[data-panel=assets] [data-asset='{bad['id']}']").first.click()
        await page.wait_for_timeout(1200)
        check("인스펙터 열림", await page.locator(".fc-drawer [data-panel=operate]").count() == 1, bad["id"])
        ops = page.locator(".fc-drawer [data-op]")
        check("인스펙터: 그 설비에 가능한 조치", await ops.count() >= 1, f"{await ops.count()}개")
        await shot("inspector")
        # 시험할 조치: 시간이 걸리는 것(진행 막대 확인)
        target_op = await page.evaluate("""id=>{const s=FacilityKit.store.data.state;const o=(s.catalog.operations||[]).filter(o=>o.targets.some(t=>t.id===id));
            return (o.find(x=>x.minutes>0&&!x.needs_drain)||o[0]).id;}""", bad["id"])
        await page.locator(f".fc-drawer .fc-op-head[data-op={target_op}]").click()
        await page.wait_for_timeout(500)
        await shot("inspector-op")
        await page.locator(f".fc-drawer [data-action=operate][data-op={target_op}]").click()
        await page.wait_for_timeout(4000)
        s = await state()
        check("조치가 작업으로 반영됨", any(x["op"] == target_op for x in s.get("work", [])) or any(hh["status"] == "applied" for hh in s["handled"][-2:]), target_op)
        check("진행 막대", await page.locator("[data-panel=work] .fc-work").count() >= 1)
        await shot("work")
        await page.keyboard.press("Escape")

        # 5. 지도에 훈련·경보 반영 + 지도에서 설비 고르기
        await page.goto(f"{a.base}/core/#datacenter")
        await page.wait_for_timeout(6000)
        check("지도: 훈련 배너", await page.locator("#dc-live [data-panel=drill]").count() >= 1)
        check("지도: 경보 설비가 빛남", await page.locator(".dc-world .fc-live[data-status=critical],.dc-world .fc-live[data-status=warning]").count() >= 1)
        await shot("map-drill")
        node = page.locator(".dc-world .fc-live[data-status=critical],.dc-world .fc-live[data-status=warning]").first
        await node.dispatch_event("click")
        await page.wait_for_timeout(1500)
        check("지도: 설비를 누르면 인스펙터와 조치", await page.locator("#dc-inspector [data-panel=operate]").count() == 1)
        await shot("map-inspector")
        # B1 층 안
        await page.locator("[data-dc-mode=building]").click()
        await page.wait_for_timeout(1500)
        await page.locator('[data-dc-floor="B1"]').first.dispatch_event("click")
        await page.wait_for_timeout(4000)
        check("B1: 설비 상태 오버레이", await page.locator(".dc-world .fc-live").count() >= 8)
        await shot("map-b1")

        # 6. 해결을 기다려 결과·기록 확인
        await page.goto(f"{a.base}/core/#module/m4-facility")
        await page.wait_for_timeout(3000)
        await page.select_option("#facility-scale", "30")
        await page.wait_for_timeout(15000)
        await page.locator("[data-panel=events]").scroll_into_view_if_needed()
        await page.wait_for_timeout(800)
        siem = await page.locator("[data-action=siem-open]").get_attribute("href")
        check("SIEM에서 분석 버튼", siem and siem.startswith("/siem/app/data-explorer/discover") and "rule.groups:facility" in siem)
        await shot("events")
        await page.locator("[data-panel=trend]").scroll_into_view_if_needed()
        await page.mouse.move(w * 0.45, 400)
        await page.wait_for_timeout(600)
        await shot("trend")

        # 7. 강사 도구: 장애 넣기·되돌리기
        await req({"action": "drill_stop"})
        await page.wait_for_timeout(2500)
        await page.locator("[data-panel=instructor]").scroll_into_view_if_needed()
        await page.select_option("#facility-fault", "crac_fail")
        await page.wait_for_timeout(400)
        await page.locator("[data-facility=inject]").click()
        await page.wait_for_timeout(4000)
        check("장애 넣기 → 되돌리기 버튼", await page.locator("[data-facility=clear]").count() >= 1)
        check("모두 되돌리기 보임(보이는 장애가 있음)", await page.locator("[data-facility=clear_all]").count() == 1)
        await shot("instructor")
        await page.locator("[data-facility=clear_all]").click()
        await page.wait_for_timeout(3500)

        # 8. 강사 반 전체 장애(원인 숨김)
        dev("")
        urllib.request.urlopen(f"{a.base}/dev/class-drill?hidden=1").read()
        await page.wait_for_timeout(5000)
        body = await page.locator(".fc-root").inner_text()
        s = await state()
        hidden = [f for f in s["faults"] if f["fault"] == "hidden"]
        check("강사 숨김 장애가 상태에 있음", len(hidden) >= 1)
        check("강사 숨김 장애: 되돌리기 없음", await page.locator("[data-facility=clear]").count() == 0)
        check("강사 장애만 있을 때 모두 되돌리기 숨김", await page.locator("[data-facility=clear_all]").count() == 0)
        check("강사 숨김 장애: 원인(장애 이름·대상) 비공개", await page.locator(".fc-fault:not([data-kind=hidden])").count() == 0 and "강사가 넣은 장애" in body)
        check("강사 진행 훈련 배너(반 전체)", await page.locator("[data-panel=drill][data-drill-kind=class]").count() >= 1)
        await page.evaluate("window.scrollTo(0,0)")
        await shot("class-drill")
        urllib.request.urlopen(f"{a.base}/dev/class-drill?stop=1").read()
        await page.wait_for_timeout(3000)

        # 9. 조회자: 조작 버튼 없음
        dev("role=viewer")
        await page.reload()
        await page.wait_for_timeout(4000)
        check("조회자: 강사 도구 없음", await page.locator("[data-panel=instructor]").count() == 0)
        check("조회자: 배속 선택 없음", await page.locator("#facility-scale").count() == 0)
        await page.locator("[data-panel=assets] [data-asset='ups-01']").first.click()
        await page.wait_for_timeout(800)
        check("조회자: 조치 버튼이 비활성", await page.locator(".fc-drawer .fc-op-head:not([disabled])").count() == 0)
        await shot("viewer")
        dev("role=admin")
        await browser.close()
    for e in errors:
        print("console error:", e)
    failed = [n for n, ok in CHECKS if not ok]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} 통과" + (" · 실패: " + ", ".join(failed) if failed else ""))
    return 1 if failed or errors else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
