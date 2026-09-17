"""Link preview generator for URLs in WhatsApp messages."""

from __future__ import annotations

import re
from typing import Any
import urllib.parse

import httpx

from waton.client.media_stream import extract_image_thumb

URL_REGEX = re.compile(r"https?://[^\s/$.?#].[^\s]*", re.IGNORECASE)


async def get_url_info(
    text: str,
    *,
    timeout: float = 5.0,
    thumbnail_width: int = 192,
) -> dict[str, Any] | None:
    """
    Scrapes OpenGraph metadata from a URL found in text to construct a link preview.
    Returns None if no URL is found or fetching fails.
    """
    match = URL_REGEX.search(text)
    if not match:
        return None

    url = match.group(0)

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client:
            headers = {
                "User-Agent": "WhatsApp/2.24.1.1 Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
            resp = await client.get(url, headers=headers)
            if resp.status_code >= 400:
                return None

            html = resp.text

            # Simple regex parser for OpenGraph and title tags
            title_match = re.search(r'<meta\s+property=["\']og:title["\']\s+content=["\'](.*?)["\']', html, re.IGNORECASE)
            if not title_match:
                title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
            title = title_match.group(1).strip() if title_match else ""

            desc_match = re.search(r'<meta\s+property=["\']og:description["\']\s+content=["\'](.*?)["\']', html, re.IGNORECASE)
            if not desc_match:
                desc_match = re.search(r'<meta\s+name=["\']description["\']\s+content=["\'](.*?)["\']', html, re.IGNORECASE)
            description = desc_match.group(1).strip() if desc_match else ""

            img_match = re.search(r'<meta\s+property=["\']og:image["\']\s+content=["\'](.*?)["\']', html, re.IGNORECASE)
            image_url = img_match.group(1).strip() if img_match else None

            if image_url and not image_url.startswith(("http://", "https://")):
                image_url = urllib.parse.urljoin(str(resp.url), image_url)

            jpeg_thumb: bytes | None = None
            if image_url:
                try:
                    img_resp = await client.get(image_url, headers=headers)
                    if img_resp.status_code == 200 and img_resp.content:
                        jpeg_thumb = extract_image_thumb(img_resp.content, max_size=thumbnail_width)
                except Exception:
                    jpeg_thumb = None

            if not title and not description:
                return None

            return {
                "canonical-url": str(resp.url),
                "matched-text": url,
                "title": title,
                "description": description,
                "originalThumbnailUrl": image_url,
                "jpegThumbnail": jpeg_thumb,
            }
    except Exception:
        return None
