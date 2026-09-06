import random
import time

import requests

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config import settings


class RetrySession:

    def __init__(self):

        self.session = requests.Session()

        self.session.headers.update({

            "User-Agent": settings.USER_AGENT,

        })

        # -----------------------------------
        # Retry Strategy
        # -----------------------------------

        retry = Retry(

            total=settings.RETRY_COUNT,

            connect=settings.RETRY_COUNT,

            read=settings.RETRY_COUNT,

            backoff_factor=settings.RETRY_BACKOFF,

            status_forcelist=(

                429,
                500,
                502,
                503,
                504,

            ),

            allowed_methods=(

                "GET",
                "HEAD",
                "OPTIONS",
                "POST",
                "PUT",
                "DELETE",
                "PATCH",

            ),

            raise_on_status=False,

        )

        adapter = HTTPAdapter(

            max_retries=retry,

            pool_connections=100,

            pool_maxsize=100,

        )

        self.session.mount(
            "http://",
            adapter,
        )

        self.session.mount(
            "https://",
            adapter,
        )

        self.session.verify = settings.VERIFY_SSL

        self.session.trust_env = True

    def request(
        self,
        method,
        url,
        **kwargs,
    ):

        kwargs.setdefault(

            "timeout",

            (

                settings.CONNECT_TIMEOUT,

                settings.REQUEST_TIMEOUT,

            ),

        )

        kwargs.setdefault(

            "allow_redirects",

            settings.FOLLOW_REDIRECTS,

        )

        try:

            response = self.session.request(

                method,

                url,

                **kwargs,

            )

            return response

        except requests.RequestException:

            delay = settings.RETRY_BACKOFF

            for _ in range(settings.RETRY_COUNT - 1):

                time.sleep(

                    delay + random.random()

                )

                delay *= 2

                try:

                    return self.session.request(

                        method,

                        url,

                        **kwargs,

                    )

                except requests.RequestException:

                    pass

        return None

    def get(self, url, **kwargs):

        return self.request(
            "GET",
            url,
            **kwargs,
        )

    def post(self, url, **kwargs):

        return self.request(
            "POST",
            url,
            **kwargs,
        )

    def put(self, url, **kwargs):

        return self.request(
            "PUT",
            url,
            **kwargs,
        )

    def delete(self, url, **kwargs):

        return self.request(
            "DELETE",
            url,
            **kwargs,
        )

    def head(self, url, **kwargs):

        return self.request(
            "HEAD",
            url,
            **kwargs,
        )

    def options(self, url, **kwargs):

        return self.request(
            "OPTIONS",
            url,
            **kwargs,
        )

    def patch(self, url, **kwargs):

        return self.request(
            "PATCH",
            url,
            **kwargs,
        )


http = RetrySession()