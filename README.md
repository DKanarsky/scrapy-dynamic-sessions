# scrapy-dynamic-sessions
A session-management extension with random proxies and User-Agents for Scrapy.

**Thanks to [scrapy-sessions](https://github.com/ThomasAitken/scrapy-sessions), [scrapy-fake-useragent](https://github.com/alecxe/scrapy-fake-useragent) and [scrapy-proxies](https://github.com/aivarsk/scrapy-proxies)!**

## Overview

This library is inspired and based on listed above projects to provide all-in-one extension for managing session for Scrapy with random proxy and User-Agent for each session.

I tried to keep all features of these projects with some additional capabilities.

Sessions are the most complicated part of these library and to understand underlying process please visit [scrapy-sessions](https://github.com/ThomasAitken/scrapy-sessions) and read its documentation.

There are two middlewares inside:

1. `CookiesMiddleware` is designed to override the default Scrapy `CookiesMiddleware`. It is an extension of the default middleware, so there shouldn't be adverse consequences from adopting it.
2. `RetryProfileMiddleware` - is designed to override the default Scrapy `RetryMiddleware` to provide a way of changing client session due to some errors. It is also an extension of the default middleware.

## Set up

Override the default middlewares:

````python
DOWNLOADER_MIDDLEWARES = {
    'scrapy.contrib.downloadermiddleware.useragent.UserAgentMiddleware': None,
    'scrapy.contrib.downloadermiddleware.retry.RetryMiddleware': None,
    'scrapy.downloadermiddlewares.cookies.CookiesMiddleware': None,
    'scrapy_dynamic_sessions.CookiesMiddleware': 700,
    'scrapy_dynamic_sessions.RetryProfileMiddleware': 710,
}
````

Enable User-Agent providers:

```python
FAKEUSERAGENT_PROVIDERS = [
    'scrapy_dynamic_sessions.ua_providers.FakeUserAgentProvider'
]
```

More about providers see [scrapy-fake-useragent](https://github.com/alecxe/scrapy-fake-useragent) documentation (all available in `scrapy-fake-useragent` providers are built in this project).

Set proxies source file:

```python
PROXY_LIST = "path/to/your/file"
```

Proxy source file example:

```
http://user:password@1.1.1.1:8080
http://2.2.2.2:1111
```

Set random proxy strategy:

```python
REUSE_PROXY = True
```

If `REUSE_PROXY` is set to `False`, each profile is generated with unique proxy if you have enough proxies. Defaults to `False`.

Enable `RetryProfileMiddleware` middleware:

```python
RETRY_ENABLED = True
```

Optionally define maximum retry times:

```python
RETRY_TIMES = 10
```

You can add additional options for retry middleware as described in official `RetryMiddleware` documentation in Scrapy.

Set `SESSIONS_PROFILES_SYNC`:

```python
SESSIONS_PROFILES_SYNC = True
```

## Miscellaneous

Since sessions are based on [scrapy-sessions](https://github.com/ThomasAitken/scrapy-sessions) they have a bit more functionality not described here, but the library can be used in a simple way just to keep proxy, User-Agent and cookies attached to specific profile updating when necessary.
