"""Render onepager.html to PDF via headless Chromium."""
from playwright.sync_api import sync_playwright
from pathlib import Path

HERE = Path(__file__).parent
HTML = HERE / "onepager.html"
PDF  = HERE / "lakebase-field-level-encryption.pdf"

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page()
    page.goto(f"file://{HTML}")
    page.wait_for_load_state("networkidle")
    page.pdf(
        path=str(PDF),
        format="A4",
        print_background=True,
        margin={"top": "10mm", "bottom": "10mm", "left": "10mm", "right": "10mm"},
        prefer_css_page_size=True,
    )
    browser.close()

size_kb = PDF.stat().st_size / 1024
print(f"Wrote {PDF} ({size_kb:.0f} KB)")
