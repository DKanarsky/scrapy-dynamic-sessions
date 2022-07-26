import base64
import logging
import random
from http.cookiejar import time2netscape
from typing import Dict, List, Union

from scrapy.http import Request, Response
from scrapy.http.cookies import CookieJar
from scrapy.utils.log import failure_to_exc_info
from scrapy.utils.misc import load_object

from .utils import format_cookie, load_proxies

logger = logging.getLogger(__name__)


class DynamicJar(CookieJar):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.needs_renewal = False
        self.has_specified_req = False
        self.times_renewed = 0


class Sessions:
    logger = logging.getLogger(__name__)

    def __init__(self, jars, profiles, spider, engine):
        self.jars=jars
        self.profiles=profiles
        self.spider=spider
        self.engine=engine

    def __repr__(self):
        out = ""
        for k in self.jars.keys():
            out += repr(self.get(k)) + "\n\n"
        out = out.rstrip("\n")
        return out

    @staticmethod
    def _flatten_cookiejar(jar):
        """Returns map object of cookies in http.Cookiejar.Cookies format
        """
        cookies = {}
        for domain, val in jar._cookies.items():
            full_cookies = list(val.values())[0]
            cookies[domain] = full_cookies.values()
        return cookies

    @staticmethod
    def _httpcookie_to_tuple(cookie):
        simple_cookie = (getattr(cookie, 'name'), getattr(cookie, 'value'))
        return simple_cookie

    @staticmethod
    def _httpcookie_to_str(cookie):
        content = getattr(cookie, 'name') + '=' + getattr(cookie, 'value')
        expires = 'expires=' + time2netscape(getattr(cookie, 'expires'))
        path = 'path=' + getattr(cookie, 'path')
        domain = 'domain=' + getattr(cookie, 'domain')
        out_str = f'{content}; {expires}; {path}; {domain}'
        return out_str

    def _get(self, session_id=0):
        return self.jars[session_id]
    
    def get(self, session_id=0, mode=None, domain=None):
        """Returns list of cookies for the given session.
        For inspection not editing.
        """
        jar = self._get(session_id)
        if not jar._cookies:
            return {}
        cookies = self._flatten_cookiejar(jar)
        if domain is None:
            # default to first domain. assume that if no domain specified, only one domain of interest
            domain = next(iter(cookies.keys()))
        cookies = cookies[domain]
        if mode == dict:
            neat_cookies = dict(self._httpcookie_to_tuple(c) for c in cookies)
        else:
            neat_cookies = [self._httpcookie_to_str(c) for c in cookies]

        return neat_cookies

    def get_profile(self, session_id=None):
        if self.profiles is not None:
            return self.profiles.ref.get(session_id, None)
        raise Exception('Can\'t use get_profile function when SESSIONS_PROFILES_SYNC is not enabled')

    def add_cookies_manually(self, cookies, url, session_id=0):
        cookies = ({"name": k, "value": v} for k, v in cookies.items())
        request = Request(url)
        formatted = filter(None, (format_cookie(c, request) for c in cookies))
        response = Response(request.url, headers={"Set-Cookie": formatted})
        jar = self._get(session_id)
        for cookie in jar.make_cookies(response, request):
            jar.set_cookie_if_ok(cookie, request)

    def clear(self, session_id=0, renewal_request=None):
        jar = self._get(session_id)
        jar.needs_renewal = True
        jar.clear()
        if self.profiles is not None:
            self.profiles._clear(session_id)

        if renewal_request is not None:
            jar.has_specified_req = True
            if renewal_request.callback is None:
                renewal_request.callback=self._renew
            renewal_request.meta.update({'_renewal': True})
            renewal_request.dont_filter=True
            self._download_request(renewal_request)

    def _download_request(self, request):
        d = self.engine._download(request, self.spider)
        d.addBoth(self.engine._handle_downloader_output, request, self.spider)
        d.addErrback(lambda f: logger.info('Error while handling downloader output',
                                        exc_info=failure_to_exc_info(f),
                                        extra={'spider': self.spider}))
        d.addBoth(lambda _: self.engine.slot.remove_request(request))
        d.addErrback(lambda f: logger.info('Error while removing request from slot',
                                        exc_info=failure_to_exc_info(f),
                                        extra={'spider': self.spider}))
        d.addBoth(lambda _: self.engine.slot.nextcall.schedule())
        d.addErrback(lambda f: logger.info('Error while scheduling new request',
                                        exc_info=failure_to_exc_info(f),
                                        extra={'spider': self.spider}))

    def _renew(self, response, **cb_kwargs):
        pass


class Proxies(object):
    """Controls proxy storage and rotation. Rotation is random"""

    def __init__(self, proxies_file_path: str) -> None:
        self._proxies = load_proxies(proxies_file_path)
        self._used_proxies = set()
        if not self._proxies:
            raise Exception(
                "There are no proxies loaded from \"%s\"",
                proxies_file_path
            )

    def update_proxies(self, proxies: Dict):
        for key in proxies.keys():
            if key not in self._proxies:
                self._proxies[key] = proxies[key]

    def get_random_proxy(self, reuse: bool = False) -> List[str]:
        """Returns random proxy

        Args:
            reuse (bool, optional): if True may return already used proxy. Defaults to False.

        Returns:
            List[str,str]: ['proxy_url', basic_auth_header('username', 'password')]
        """

        proxy_addresses = set(self._proxies.keys())
        if not self.reuse:
            fresh_proxies = proxy_addresses - self._used_proxies
            if len(fresh_proxies) == 0:
                logger.warning("There is no fresh proxy left! Reuse any.")
            else:
                proxy_addresses = fresh_proxies
        proxy_addr = random.choice(list(proxy_addresses))
        proxy_auth = self._proxies[proxy_addr]
        # Add proxy to used ones
        self._used_proxies.add(proxy_addr)
        return proxy_addr, proxy_auth

    def del_proxy(self, proxy_address):
        if proxy_address in self._proxies:
            del self._proxies[proxy_address]
            logger.info(
                "Delete proxy %s. %d proxies left", 
                proxy_address, len(self._proxies)
            )


class UserAgents(object):
    """Controls UserAgent rotation. Rotation is random"""

    def __init__(self, provider_path, settings):
        self._ua_provider = self._get_provider(provider_path, settings)

    def get_random_ua(self):
        return self._ua_provider.get_random_ua()

    def _get_provider(self, provider_paths, settings):
        self.providers_paths = provider_paths

        if not self.providers_paths:
            raise Exception("Must provide UserAgent providers")
            # self.providers_paths = [FAKE_USERAGENT_PROVIDER_PATH]

        provider = None
        # We try to use any of the user agent providers specified in the config (priority order)
        for provider_path in self.providers_paths:
            try:
                provider = load_object(provider_path)(settings)
                logger.debug("Loaded User-Agent provider: %s", provider_path)
                break
            except Exception:  # Provider can throw anything
                logger.info('Error loading User-Agent provider: %s', provider_path)

        if not provider:
            raise Exception("There are no providers loaded")

        logger.info("Using '%s' as the User-Agent provider", type(provider))
        return provider


class Profiles(object):
    """Controls profile storage and rotation. Rotation is random"""

    def __init__(self, proxies: Proxies = None, ua: UserAgents = None, reuse_proxy:bool = False):
        self.proxies = proxies
        self.ua = ua
        self.reuse = reuse_proxy
        #TODO: rename ref for it is the same as profile
        self.ref = {}

    @property
    def generated_profiles(self):
        return len(self.ref)

    def _clear(self, session_id):
        if session_id not in self.ref:
            logger.debug(
                "Profile with id=%s does not exist (may have been removed)",
                session_id
            )
        else:
            del self.ref[session_id]
            logger.info(
                "Remove profile with id=%s",
                session_id
            )

    def new_session(self, session_id: Union[int,None] = None) -> int:
        """Generate random session

        Args:
            session_id (Union[int,None], optional): session to replace, if None creates new one.
            Defaults to None.

        Returns:
            int: replaced or created session_id
        """

        if session_id is None:
            new_session_id = self.generated_profiles
        else: 
            new_session_id = session_id
        self.ref[new_session_id] = self.random_profile()
        logger.info(
            "Generate new session with id: %s and meta: %s",
            new_session_id, self.ref[new_session_id]
        )
        return new_session_id

    def random_profile(self):
        meta = {}
        if self.proxies:
            meta['proxy'] = self.proxies.get_random_proxy(self.reuse)
        if self.ua:
            meta['user-agent'] = self.ua.get_random_ua()
        return meta

    def add_profile(self, request, session_id=None):
        """Adds session to request. If session_id is None generates random one"""

        if session_id is None:
            session_id = self.new_session()
        profile = self.ref[session_id]
        if 'proxy' in profile:
            request.meta['proxy'] = profile['proxy'][0]
            if profile['proxy'][1]:
                basic_auth = 'Basic ' + base64.b64encode(profile['proxy'][1].encode()).decode()
                request.headers['Proxy-Authorization'] = basic_auth
        if 'user-agent' in profile:
            request.headers['User-Agent'] = profile['user-agent']

    def del_profile(self, session_id):
        if session_id in self.ref:
            del self.ref[session_id]
            logger.debug(
                "Delete profile with id=%s",
                session_id
            )

