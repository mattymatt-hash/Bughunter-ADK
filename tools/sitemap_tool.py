import xml.etree.ElementTree as ET

from urllib.parse import urljoin, urlparse

from models.sitemap_result import SitemapResult
from tools.retry import http


class SitemapTool:

    # -----------------------------------
    # Interesting URL paths
    # -----------------------------------

    INTERESTING_PATHS = (
        "/api/",
        "/graphql",
        "/v1/",
        "/v2/",
        "/v3/",
        "/oauth",
        "/auth",
        "/swagger",
        "/openapi",
        "/docs",
        "/upload",
        "/download",
        "/webhook",
        "/webhooks",
        "/admin",
        "/dashboard",
        "/internal",
    )

    # -----------------------------------
    # Safety / recursion limits
    # -----------------------------------

    MAX_SITEMAPS = 100

    # -----------------------------------
    # XML namespaces
    # -----------------------------------

    NAMESPACES = {
        "sm": "http://www.sitemaps.org/schemas/sitemap/0.9",
        "image": "http://www.google.com/schemas/sitemap-image/1.1",
        "news": "http://www.google.com/schemas/sitemap-news/0.9",
        "xhtml": "http://www.w3.org/1999/xhtml",
    }

    def scan(self, base_url):

        result = SitemapResult()

        #
        # Normalize base URL
        #

        base_url = base_url.strip().rstrip("/")

        if not base_url.startswith(("http://", "https://")):

            base_url = "https://" + base_url

        #
        # Only use the hostname for sitemap scope
        #

        parsed = urlparse(base_url)

        if not parsed.hostname:

            return result

        base_hostname = parsed.hostname.lower()

        #
        # Track every sitemap we've already processed.
        #

        visited = set()

        #
        # Start recursive sitemap crawl.
        #

        root_sitemap = (
            base_url + "/sitemap.xml"
        )

        self._crawl_sitemap(
            sitemap_url=root_sitemap,
            result=result,
            visited=visited,
            base_hostname=base_hostname,
        )

        #
        # Remove duplicates
        #

        result.urls = sorted(
            set(result.urls)
        )

        result.images = sorted(
            set(result.images)
        )

        result.apis = sorted(
            set(result.apis)
        )

        result.news = sorted(
            set(result.news)
        )

        result.alternate_languages = sorted(
            set(result.alternate_languages)
        )

        result.sitemaps = sorted(
            set(result.sitemaps)
        )

        #
        # Sitemap was found if at least one
        # sitemap was successfully parsed.
        #

        if visited:

            result.found = True

        return result

    # -----------------------------------
    # Recursive Sitemap Crawler
    # -----------------------------------

    def _crawl_sitemap(
        self,
        sitemap_url,
        result,
        visited,
        base_hostname,
    ):

        #
        # Normalize sitemap URL
        #

        sitemap_url = sitemap_url.strip()

        if not sitemap_url:

            return

        #
        # Only process HTTP/HTTPS URLs.
        #

        parsed = urlparse(sitemap_url)

        if parsed.scheme not in (
            "http",
            "https",
        ):

            return

        if not parsed.hostname:

            return

        #
        # Prevent recursive sitemap crawling
        # outside the target host.
        #

        hostname = parsed.hostname.lower()

        if hostname != base_hostname:

            return

        #
        # Normalize trailing slash.
        #

        sitemap_url = sitemap_url.rstrip("/")

        #
        # Already processed?
        #

        if sitemap_url in visited:

            return

        #
        # Prevent runaway sitemap indexes.
        #

        if len(visited) >= self.MAX_SITEMAPS:

            return

        visited.add(sitemap_url)

        #
        # Record sitemap.
        #

        result.sitemaps.append(
            sitemap_url
        )

        #
        # Download sitemap.
        #

        try:

            response = http.get(
                sitemap_url,
            )

        except Exception:

            return

        if response is None:

            return

        if response.status_code != 200:

            return

        #
        # Fix character encoding.
        #

        try:

            if response.apparent_encoding:

                response.encoding = (
                    response.apparent_encoding
                )

        except Exception:

            pass

        #
        # Parse XML.
        #

        try:

            root = ET.fromstring(
                response.text
            )

        except Exception:

            return

        #
        # Determine whether this is:
        #
        # sitemap index:
        #   <sitemapindex>
        #
        # or URL set:
        #   <urlset>
        #

        root_name = self._local_name(
            root.tag
        ).lower()

        # -----------------------------------
        # Sitemap Index
        # -----------------------------------

        if root_name == "sitemapindex":

            self._process_sitemap_index(
                root=root,
                sitemap_url=sitemap_url,
                result=result,
                visited=visited,
                base_hostname=base_hostname,
            )

            return

        # -----------------------------------
        # URL Set
        # -----------------------------------

        if root_name == "urlset":

            self._process_urlset(
                root=root,
                sitemap_url=sitemap_url,
                result=result,
            )

            return

        #
        # Some sitemap providers don't use
        # perfectly standard root formatting.
        #
        # Fall back to checking for sitemap
        # and URL elements.
        #

        has_sitemap_nodes = any(
            self._local_name(
                element.tag
            ).lower() == "sitemap"
            for element in root.iter()
        )

        has_url_nodes = any(
            self._local_name(
                element.tag
            ).lower() == "url"
            for element in root.iter()
        )

        if has_sitemap_nodes:

            self._process_sitemap_index(
                root=root,
                sitemap_url=sitemap_url,
                result=result,
                visited=visited,
                base_hostname=base_hostname,
            )

        elif has_url_nodes:

            self._process_urlset(
                root=root,
                sitemap_url=sitemap_url,
                result=result,
            )

    # -----------------------------------
    # Process Sitemap Index
    # -----------------------------------

    def _process_sitemap_index(
        self,
        root,
        sitemap_url,
        result,
        visited,
        base_hostname,
    ):

        for element in root.iter():

            if self._local_name(
                element.tag
            ).lower() != "sitemap":

                continue

            loc = self._find_child_text(
                element,
                "loc",
            )

            if not loc:

                continue

            child_sitemap = urljoin(
                sitemap_url,
                loc.strip(),
            )

            #
            # Record it before recursion.
            #

            result.sitemaps.append(
                child_sitemap
            )

            #
            # Recursively process child sitemap.
            #

            self._crawl_sitemap(
                sitemap_url=child_sitemap,
                result=result,
                visited=visited,
                base_hostname=base_hostname,
            )

    # -----------------------------------
    # Process URL Set
    # -----------------------------------

    def _process_urlset(
        self,
        root,
        sitemap_url,
        result,
    ):

        for element in root.iter():

            if self._local_name(
                element.tag
            ).lower() != "url":

                continue

            #
            # URL
            #

            loc = self._find_child_text(
                element,
                "loc",
            )

            if loc:

                url = urljoin(
                    sitemap_url,
                    loc.strip(),
                )

                self._add_url(
                    result,
                    url,
                )

            #
            # Images
            #

            for child in element.iter():

                if self._local_name(
                    child.tag
                ).lower() != "loc":

                    continue

                namespace = self._namespace(
                    child.tag
                )

                if namespace == (
                    self.NAMESPACES["image"]
                ):

                    if child.text:

                        image_url = urljoin(
                            sitemap_url,
                            child.text.strip(),
                        )

                        result.images.append(
                            image_url
                        )

            #
            # News
            #

            for child in element.iter():

                if self._local_name(
                    child.tag
                ).lower() != "news":

                    continue

                title = self._find_child_text(
                    child,
                    "title",
                )

                if title:

                    result.news.append(
                        title.strip()
                    )

                else:

                    result.news.append(
                        "News Entry"
                    )

            #
            # Alternate languages
            #

            for child in element.iter():

                if self._local_name(
                    child.tag
                ).lower() != "link":

                    continue

                namespace = self._namespace(
                    child.tag
                )

                if namespace != (
                    self.NAMESPACES["xhtml"]
                ):

                    continue

                href = child.attrib.get(
                    "href",
                )

                if href:

                    alternate_url = urljoin(
                        sitemap_url,
                        href.strip(),
                    )

                    result.alternate_languages.append(
                        alternate_url
                    )

    # -----------------------------------
    # Add URL
    # -----------------------------------

    def _add_url(
        self,
        result,
        url,
    ):

        if not url:

            return

        url = url.strip()

        if not url:

            return

        #
        # Only HTTP/HTTPS URLs.
        #

        parsed = urlparse(url)

        if parsed.scheme not in (
            "http",
            "https",
        ):

            return

        #
        # Add normal URL.
        #

        result.urls.append(
            url
        )

        #
        # Classify interesting paths.
        #

        lower_url = url.lower()

        if any(
            path in lower_url
            for path in self.INTERESTING_PATHS
        ):

            result.apis.append(
                url
            )

    # -----------------------------------
    # XML Helpers
    # -----------------------------------

    @staticmethod
    def _local_name(tag):

        if "}" in tag:

            return tag.rsplit(
                "}",
                1,
            )[1]

        return tag

    @staticmethod
    def _namespace(tag):

        if tag.startswith("{"):

            return tag[1:].split(
                "}",
                1,
            )[0]

        return ""

    def _find_child_text(
        self,
        element,
        name,
    ):

        for child in element:

            if (
                self._local_name(
                    child.tag
                ).lower()
                == name.lower()
            ):

                if child.text:

                    return child.text.strip()

        return None