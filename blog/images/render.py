"""Render the comparison and bypass HTML files to PNG via headless Chromium."""
from playwright.sync_api import sync_playwright
from pathlib import Path

HERE = Path(__file__).parent

PAGES = [
    ("comparison.html",                 "comparison.png",                 1600, 1100),
    ("bypass.html",                     "bypass.png",                     1300, 900),
    ("at_rest_vs_column.html",          "at_rest_vs_column.png",          1500, 1300),
    ("onprem_encrypt_to_lakebase.html", "onprem_encrypt_to_lakebase.png", 1600, 1700),
]

with sync_playwright() as p:
    browser = p.chromium.launch()
    for html_name, png_name, w, h in PAGES:
        ctx = browser.new_context(viewport={"width": w, "height": h}, device_scale_factor=2)
        page = ctx.new_page()
        page.goto(f"file://{HERE / html_name}")
        page.wait_for_load_state("networkidle")
        page.screenshot(path=str(HERE / png_name), full_page=True)
        print(f"  wrote {png_name}")
        ctx.close()
    browser.close()
