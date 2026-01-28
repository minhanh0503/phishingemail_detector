import re
from urllib.parse import urlparse


URL_REGEX = re.compile(
    r"(https?://[^\s<>\"']+|www\.[^\s<>\"']+)",
    re.IGNORECASE
)


def extract_urls(text: str) -> list[str]:
    urls = re.findall(URL_REGEX, text)
    return [normalize_url(u) for u in urls]


def normalize_url(url: str) -> str:
    if url.startswith("www."):
        return "http://" + url
    return url


def extract_domain_from_url(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc.lower()
