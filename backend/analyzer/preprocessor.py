import re
from urllib.parse import urlparse
import string

#URL clean
URL_REGEX = re.compile(
    r"(https?://[^\s]+|www\.[^\s]+)",
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
# Remove duplicate URL
def unique_urls(urls: list[str]) -> list[str]:
    return list(dict.fromkeys(urls))

#Text clean
def extract_domain(email: str) -> str:
    if "@" not in email:
        return ""
    return email.split("@", 1)[1].lower()

def extract_local_part(email: str) -> str:
    if "@" not in email:
        return ""
    return email.split("@", 1)[0].lower()

def extract_tld(domain: str) -> str:
    return domain.split(".")[-1]

def normalize_text(text: str) -> str:
    return " ".join(text.split())

# Remove punctuation and special characters from text
def remove_punctuation(text: str) -> str:
    return text.translate(str.maketrans("", "", string.punctuation))

def lowercase(text: str) -> str:
    return text.lower()