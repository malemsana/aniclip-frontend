import requests
from datetime import datetime
from xml.etree.ElementTree import Element, SubElement, ElementTree

BASE_API = "https://aniclip-backend.onrender.com/api"
ARCHIVE_ENDPOINT = "/animes/archive"

SITE_URL = "https://aniclips.site"
OUTPUT_FILE = "sitemap.xml"


def fetch_all_animes():
    page = 1
    items = []

    print("📡 Fetching anime archive...")

    while True:
        url = f"{BASE_API}{ARCHIVE_ENDPOINT}?page={page}&seed=sitemap"
        res = requests.get(url, timeout=30)

        if res.status_code != 200:
            raise RuntimeError(f"API error on page {page}")

        data = res.json()
        if not data:
            break

        items.extend(data)
        print(f"  • Page {page}: {len(data)} items")

        page += 1

    return items


def build_sitemap(items):
    urlset = Element(
        "urlset",
        xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
    )

    today = datetime.utcnow().date().isoformat()
    seen = set()

    for item in items:
        name = item.get("name")
        if not name or name in seen:
            continue

        seen.add(name)

        url = SubElement(urlset, "url")

        loc = SubElement(url, "loc")
        loc.text = f"{SITE_URL}/anime.html?name={name}"

        lastmod = SubElement(url, "lastmod")
        lastmod.text = today

    return urlset


def main():
    items = fetch_all_animes()
    print(f"📦 Total items fetched: {len(items)}")

    sitemap = build_sitemap(items)

    if len(sitemap) == 0:
        raise RuntimeError("No URLs generated — 'name' field missing")

    ElementTree(sitemap).write(
        OUTPUT_FILE,
        encoding="utf-8",
        xml_declaration=True
    )

    print("✅ sitemap.xml generated successfully")


if __name__ == "__main__":
    main()
