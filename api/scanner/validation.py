import re

CANONICAL_URL_REGEX = re.compile(r'(https?://[^\s\]\)\>\"\']+)')
MAX_URL_LENGTH = 2048

def canonicalize_url(raw_input: str) -> str:
    """Sanitizes raw user input into a clean, canonical HTTP/HTTPS URL."""
    clean_url = raw_input.strip()
    if len(clean_url) > MAX_URL_LENGTH:
        raise ValueError(f"URL exceeds maximum allowed length of {MAX_URL_LENGTH} characters.")
        
    if not clean_url.startswith("http://") and not clean_url.startswith("https://"):
        clean_url = "https://" + clean_url
    match = CANONICAL_URL_REGEX.match(clean_url)
    if match:
        clean_url = match.group(1)
        
    if len(clean_url) > MAX_URL_LENGTH:
        raise ValueError(f"URL exceeds maximum allowed length of {MAX_URL_LENGTH} characters.")
        
    return clean_url

def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("URL must not be empty")
    if len(value) > MAX_URL_LENGTH:
        raise ValueError(f"URL exceeds maximum allowed length of {MAX_URL_LENGTH} characters.")
    if "://" not in value:
        value = "https://" + value
    return value
