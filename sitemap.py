import requests
from datetime import datetime
from xml.etree.ElementTree import Element, SubElement, ElementTree

BASE_API = "https://aniclip-backend.onrender.com/api"
ARCHIVE_ENDPOINT = "/animes/archive"
SITE_URL = "https://aniclip.site"   # change if needed
OUTPUT_FILE = "sitemap.xml"


def fetch_all_animes():
    page = 1
    all_animes = []

    print("📡 Fetching anime archive...")

    while True:
        url = f"{BASE_API}{ARCHIVE_ENDPOINT}?page={page}&seed=sitemap"
        res = requests.get(url, timeout=30)

        if res.status_code != 200:
            raise Exception(f"API error on page {page}: {res.status_code}")

        data = res.json()

        if not data or len(data) == 0:
            break

        all_animes.extend(data)
        print(f"  • Page {page}: {len(data)} items")

        page += 1

    return all_animes


def build_sitemap(animes):
    urlset = Element(
        "urlset",
        xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
    )

    today = datetime.utcnow().date().isoformat()
    seen = set()

    for anime in animes:
        slug = anime.get("slug") or anime.get("name")
        if not slug or slug in seen:
            continue

        seen.add(slug)

        url = SubElement(urlset, "url")

        loc = SubElement(url, "loc")
        loc.text = f"{SITE_URL}/anime/{slug}"

        lastmod = SubElement(url, "lastmod")
        lastmod.text = today

        priority = SubElement(url, "priority")
        priority.text = "0.8"

    return urlset


def main():
    animes = fetch_all_animes()
    print(f"📦 Total unique anime: {len(animes)}")

    sitemap = build_sitemap(animes)

    tree = ElementTree(sitemap)
    tree.write(OUTPUT_FILE, encoding="utf-8", xml_declaration=True)

    print("✅ sitemap.xml generated")


if __name__ == "__main__":
    main()
