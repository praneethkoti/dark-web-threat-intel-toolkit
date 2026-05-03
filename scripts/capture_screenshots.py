"""
Capture screenshots of the running Streamlit dashboard (port 8502).
Saves PNGs to docs/screenshots/.

Usage:
    python scripts/capture_screenshots.py
"""
from __future__ import annotations

import time
from pathlib import Path

BASE_URL = "http://localhost:8502"
OUT_DIR  = Path(__file__).resolve().parent.parent / "docs" / "screenshots"
OUT_DIR.mkdir(parents=True, exist_ok=True)

VIEWPORT = {"width": 1400, "height": 900}

# (file_slug, partial sidebar label text)
PAGES = [
    ("overview",    "Overview"),
    ("threat_feed", "Threat Feed"),
    ("ioc_explorer","IOC Explorer"),
    ("trends",      "Trends"),
    ("report",      "Report Generator"),
    ("summarizer",  "AI Summarizer"),
]


def wait_for_streamlit(page, timeout_ms: int = 15_000) -> None:
    """Wait until the Streamlit running spinner disappears."""
    try:
        page.wait_for_selector('[data-testid="stStatusWidget"]', timeout=3000)
        page.wait_for_selector('[data-testid="stStatusWidget"]', state="hidden", timeout=timeout_ms)
    except Exception:
        pass


def click_nav(page, label: str) -> bool:
    """Click the sidebar radio option whose text contains *label*."""
    # Streamlit renders st.sidebar.radio as <label> elements inside a radiogroup
    try:
        labels = page.locator('[data-testid="stSidebar"] label')
        for i in range(labels.count()):
            el = labels.nth(i)
            txt = (el.inner_text() or "").strip()
            if label.lower() in txt.lower():
                el.click()
                return True
    except Exception:
        pass
    return False


def capture_page(pw_page, slug: str, label: str) -> None:
    clicked = click_nav(pw_page, label)
    if not clicked:
        print(f"  WARNING: nav item '{label}' not found")
    wait_for_streamlit(pw_page)
    time.sleep(2)  # let charts / dataframes render
    out = OUT_DIR / f"{slug}.png"
    pw_page.screenshot(path=str(out), full_page=False)
    kb = out.stat().st_size // 1024
    print(f"  {'OK' if clicked else 'FALLBACK':<8} {out.name:<30} {kb} KB")


def main() -> None:
    from playwright.sync_api import sync_playwright

    print(f"Output dir : {OUT_DIR}")
    print(f"Dashboard  : {BASE_URL}\n")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport=VIEWPORT)
        pw_page  = context.new_page()

        # Initial load
        pw_page.goto(BASE_URL, wait_until="networkidle", timeout=30_000)
        wait_for_streamlit(pw_page)
        time.sleep(3)

        for slug, label in PAGES:
            capture_page(pw_page, slug, label)

        browser.close()

    print("\nDone — screenshots saved to docs/screenshots/")


if __name__ == "__main__":
    main()
