

from urllib.parse import urlparse
def validate_url(url):
    try:
        parsed_url = urlparse(url.strip())
        return (
            parsed_url.scheme in ("http", "https")
            and bool(parsed_url.netloc)
        )
    except Exception:
        return False
