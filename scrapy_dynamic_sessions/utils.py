import logging
import re

logger = logging.getLogger(__name__)


def load_proxies(path):
    proxies = {}
    fin = open(path)
    try:
        for line in fin.readlines():
            parts = re.match('(\w+://)([^:]+?:[^@]+?@)?(.+)', line.strip())
            if not parts:
                continue

            # Cut trailing @
            if parts.group(2):
                user_pass = parts.group(2)[:-1]
            else:
                user_pass = ''

            proxies[parts.group(1) + parts.group(3)] = user_pass
    finally:
        fin.close()
        return proxies


def format_cookie(cookie, request):
    """
    Given a dict consisting of cookie components, return its string representation.
    Decode from bytes if necessary.
    """
    decoded = {}
    for key in ("name", "value", "path", "domain"):
        if cookie.get(key) is None:
            if key in ("name", "value"):
                msg = "Invalid cookie found in request {}: {} ('{}' is missing)"
                logger.warning(msg.format(request, cookie, key))
                return
            continue
        if isinstance(cookie[key], str):
            decoded[key] = cookie[key]
        else:
            try:
                decoded[key] = cookie[key].decode("utf8")
            except UnicodeDecodeError:
                logger.warning("Non UTF-8 encoded cookie found in request %s: %s",
                                request, cookie)
                decoded[key] = cookie[key].decode("latin1", errors="replace")

    cookie_str = f"{decoded.pop('name')}={decoded.pop('value')}"
    for key, value in decoded.items():  # path, domain
        cookie_str += f"; {key.capitalize()}={value}"
    return cookie_str

