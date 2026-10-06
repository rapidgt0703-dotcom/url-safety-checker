from urllib.parse import urlparse
import ipaddress
import re


def extract_features(url):

    features = {}

    # --------------------------------------------------
    # Basic URL features
    # --------------------------------------------------

    features["URL Length"] = len(url)

    features["Uses HTTPS"] = url.lower().startswith("https://")

    features["Number of Dots"] = url.count(".")

    features["Number of Hyphens"] = url.count("-")

    features["Number of Digits"] = sum(
        c.isdigit() for c in url
    )

    # --------------------------------------------------
    # Additional URL structure features
    # --------------------------------------------------

    features["Number of Slashes"] = url.count("/")

    features["Number of Question Marks"] = url.count("?")

    features["Number of Equals"] = url.count("=")

    features["Number of Ampersands"] = url.count("&")

    features["Number of Special Characters"] = sum(
        not c.isalnum() for c in url
    )

    # --------------------------------------------------
    # Parse URL
    # --------------------------------------------------

    parsed = urlparse(url)

    domain = parsed.netloc.lower()

    # Remove username/password from netloc for domain analysis
    clean_domain = domain

    if "@" in clean_domain:
        clean_domain = clean_domain.split("@")[-1]

    # Remove port
    hostname = parsed.hostname or ""

    features["Domain"] = hostname

    features["Domain Length"] = len(hostname)

    features["Path Length"] = len(parsed.path)

    # --------------------------------------------------
    # IP address detection
    # --------------------------------------------------

    try:
        ipaddress.ip_address(hostname)
        features["Has IP Address"] = True
    except ValueError:
        features["Has IP Address"] = False

    # --------------------------------------------------
    # @ symbol detection
    # --------------------------------------------------

    features["Has @ Symbol"] = "@" in url

    # --------------------------------------------------
    # Punycode detection
    # Example: xn--example
    # --------------------------------------------------

    features["Has Punycode"] = "xn--" in hostname.lower()

    # --------------------------------------------------
    # Subdomain count
    # --------------------------------------------------

    domain_parts = hostname.split(".")

    if len(domain_parts) >= 3:
        features["Number of Subdomains"] = len(domain_parts) - 2
    else:
        features["Number of Subdomains"] = 0

    # --------------------------------------------------
    # URL encoded characters
    # Example: %20, %2F
    # --------------------------------------------------

    features["Has URL Encoding"] = bool(
        re.search(r"%[0-9A-Fa-f]{2}", url)
    )

    features["Number of Encoded Characters"] = len(
        re.findall(r"%[0-9A-Fa-f]{2}", url)
    )

    # --------------------------------------------------
    # Unusual port detection
    # --------------------------------------------------

    port = parsed.port

    features["Has Unusual Port"] = (
        port is not None and
        port not in [80, 443]
    )

    features["Port Number"] = port if port else 0

    # --------------------------------------------------
    # Double slash detection
    # --------------------------------------------------

    # Remove protocol before checking
    url_without_protocol = re.sub(
        r"^https?://",
        "",
        url,
        flags=re.IGNORECASE
    )

    features["Has Double Slash"] = "//" in url_without_protocol

    # --------------------------------------------------
    # URL shortener detection
    # --------------------------------------------------

    shortener_domains = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "buff.ly",
        "ow.ly",
        "cutt.ly",
        "shorturl.at",
        "rebrand.ly"
    ]

    features["Is URL Shortener"] = any(
        hostname == shortener or
        hostname.endswith("." + shortener)
        for shortener in shortener_domains
    )

    # --------------------------------------------------
    # Suspicious TLD detection
    # --------------------------------------------------

    suspicious_tlds = [
        ".xyz",
        ".top",
        ".click",
        ".link",
        ".zip",
        ".review",
        ".country",
        ".stream",
        ".download"
    ]

    features["Has Suspicious TLD"] = any(
        hostname.endswith(tld)
        for tld in suspicious_tlds
    )

    # --------------------------------------------------
    # Credential information in URL
    # Example:
    # https://user:password@example.com
    # --------------------------------------------------

    features["Contains Credentials"] = (
        parsed.username is not None or
        parsed.password is not None
    )

    # --------------------------------------------------
    # Executable / downloadable file detection
    # --------------------------------------------------

    dangerous_extensions = [
        ".exe",
        ".apk",
        ".bat",
        ".cmd",
        ".scr",
        ".zip",
        ".rar",
        ".msi"
    ]

    path_lower = parsed.path.lower()

    features["Has Dangerous File Extension"] = any(
        path_lower.endswith(ext)
        for ext in dangerous_extensions
    )

    # --------------------------------------------------
    # Fragment detection
    # --------------------------------------------------

    features["Has Fragment"] = bool(parsed.fragment)

    # --------------------------------------------------
    # Query length
    # --------------------------------------------------

    features["Query Length"] = len(parsed.query)

    # --------------------------------------------------
    # Suspicious words
    # --------------------------------------------------

    suspicious_words = [
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "confirm",
        "password",
        "signin",
        "bank",
        "payment",
        "recover",
        "wallet",
        "authenticate",
        "authorization"
    ]

    url_lower = url.lower()

    features["Suspicious Words"] = sum(
        word in url_lower
        for word in suspicious_words
    )

    # --------------------------------------------------
    # Login-related words
    # --------------------------------------------------

    login_words = [
        "login",
        "signin",
        "sign-in",
        "authenticate",
        "authentication"
    ]

    features["Login Keywords"] = sum(
        word in url_lower
        for word in login_words
    )

    # --------------------------------------------------
    # Final return
    # --------------------------------------------------

    return features