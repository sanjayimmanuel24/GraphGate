# (c) 2009-2024 Martin Wendt and contributors; see WsgiDAV https://github.com/mar10/wsgidav
# Original PyFileServer (c) 2005 Ho Chun Wei.
# Licensed under the MIT license:
# http://www.opensource.org/licenses/mit-license.php
"""
WSGI application that handles one single WebDAV request.
"""

from urllib.parse import unquote, urlparse

from wsgidav import util, xml_tools
from wsgidav.dav_error import (
    HTTP_BAD_GATEWAY,
    HTTP_BAD_REQUEST,
    HTTP_CONFLICT,
    HTTP_CREATED,
    HTTP_FAILED_DEPENDENCY,
    HTTP_FORBIDDEN,
    HTTP_INTERNAL_ERROR,
    HTTP_MEDIATYPE_NOT_SUPPORTED,
    HTTP_METHOD_NOT_ALLOWED,
    HTTP_NO_CONTENT,
    HTTP_NOT_FOUND,
    HTTP_NOT_IMPLEMENTED,
    HTTP_OK,
    HTTP_PRECONDITION_FAILED,
    HTTP_RANGE_NOT_SATISFIABLE,
    DAVError,
    PRECONDITION_CODE_LockTokenMismatch,
    PRECONDITION_CODE_PropfindFiniteDepth,
    as_DAVError,
    get_http_status_string,
)
from wsgidav.util import checked_etag, etree

_logger = util.get_module_logger(__name__)

DEFAULT_BLOCK_SIZE = 8192


# ========================================================================
# RequestServer
# ========================================================================
class RequestServer:
    def __init__(self, dav_provider):
        self._davProvider = dav_provider
        self.allow_propfind_infinite = True
        self._verbose = 3
        self.block_size = DEFAULT_BLOCK_SIZE
        # _logger.debug("RequestServer: __init__")

        self._possible_methods = ["OPTIONS", "HEAD", "GET", "PROPFIND"]
        # if self._davProvider.prop_manager is not None:
        #     self._possible_methods.extend( [ "PROPFIND" ] )
        if not self._davProvider.is_readonly():
            self._possible_methods.extend(
                ["PUT", "DELETE", "COPY", "MOVE", "MKCOL", "PROPPATCH", "POST"]
            )
            # if self._davProvider.prop_manager is not None:
            #     self._possible_methods.extend( [ "PROPPATCH" ] )
            if self._davProvider.lock_manager is not None:
                self._possible_methods.extend(["LOCK", "UNLOCK"])

    def _fail(self, value, context_info=None, src_exception=None, err_condition=None):
        """Wrapper to raise (and log) DAVError."""
        util.fail(
            value,
            context_info,
            src_exception=src_exception,
            err_condition=err_condition,
        )

    def do_GET(self, environ, start_response):
        return self._send_resource(environ, start_response, is_head_method=False)

    def _send_resource(self, environ, start_response, is_head_method):
        """
        If-Range
            If the entity is unchanged, send me the part(s) that I am missing;
            otherwise, send me the entire new entity
            If-Range: "737060cd8c284d8af7ad3082f209582d"

        @see: http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.27
        """
        path = environ["PATH_INFO"]
        res = self._davProvider.get_resource_inst(path, environ)

        if util.get_content_length(environ) != 0:
            self._fail(
                HTTP_MEDIATYPE_NOT_SUPPORTED,
                "The server does not handle any body content.",
            )
        elif environ.setdefault("HTTP_DEPTH", "0") != "0":
            self._fail(HTTP_BAD_REQUEST, "Only Depth: 0 supported.")
        elif res is None:
            self._fail(HTTP_NOT_FOUND, path)
        elif res.is_collection:
            self._fail(
                HTTP_FORBIDDEN,
                "Directory browsing is not enabled."
                "(to enable it add WsgiDavDirBrowser to the middleware_stack "
                "option and set dir_browser.enabled = True option.)",
            )

        self._evaluate_if_headers(res, environ)

        filesize = res.get_content_length()
        if filesize is None:
            filesize = -1  # flag logic to read until EOF

        last_modified = res.get_last_modified()
        if last_modified is None:
            last_modified = -1

        etag = checked_etag(res.get_etag(), allow_none=True)
        if etag is None:
            etag = "[]"

        # Ranges
        do_ignore_ranges = (
            not res.support_content_length()
            or not res.support_ranges()
            or filesize == 0
        )
        if (
            "HTTP_RANGE" in environ
            and "HTTP_IF_RANGE" in environ
            and not do_ignore_ranges
        ):
            if_range = environ["HTTP_IF_RANGE"]
            # Try as http-date first (Return None, if invalid date string)
            secstime = util.parse_time_string(if_range)
            if secstime:
                # cast to integer, as last_modified may be a floating point number
                if int(last_modified) != secstime:
                    do_ignore_ranges = True
            else:
                # Use as entity tag
                if_range = if_range.strip('" ')
                if etag is None or if_range != etag:
                    do_ignore_ranges = True

        is_partial_ranges = False
        if "HTTP_RANGE" in environ and not do_ignore_ranges:
            is_partial_ranges = True
            list_ranges, _totallength = util.obtain_content_ranges(
                environ["HTTP_RANGE"], filesize
            )
            if len(list_ranges) == 0:
                # No valid ranges present
                self._fail(HTTP_RANGE_NOT_SATISFIABLE, "No valid ranges present")

            # More than one range present -> take only the first range, since
            # multiple range returns require multipart, which is not supported
            # obtain_content_ranges supports more than one range in case the above
            # behaviour changes in future
            (range_start, range_end, range_length) = list_ranges[0]
        else:
            (range_start, range_end, range_length) = (0, filesize - 1, filesize)

        # Content Processing
        mimetype = res.get_content_type()  # provider.get_content_type(path)

        response_headers = []
        if res.support_content_length():
            # Content-length must be of type string
            response_headers.append(("Content-Length", str(range_length)))
        if res.support_modified():
            response_headers.append(
                ("Last-Modified", util.get_rfc1123_time(last_modified))
            )
        response_headers.append(("Content-Type", mimetype))
        response_headers.append(("Date", util.get_rfc1123_time()))
        if res.support_etag():
            response_headers.append(("ETag", f'"{etag}"'))

        if res.support_ranges():
            response_headers.append(("Accept-Ranges", "bytes"))

        if "response_headers" in environ["wsgidav.config"]:
            custom_headers = environ["wsgidav.config"]["response_headers"]
            for header, value in custom_headers:
                response_headers.append((header, value))

        res.finalize_headers(environ, response_headers)

        if is_partial_ranges:
            response_headers.append(
                (
                    "Content-Range",
                    f"bytes {range_start}-{range_end}/{filesize}",
                )
            )
            start_response("206 Partial Content", response_headers)
        else:
            start_response("200 OK", response_headers)

        # Return empty body for HEAD requests
        if is_head_method:
            yield b""
            return

        fileobj = res.get_content()

        if not do_ignore_ranges:
            fileobj.seek(range_start)

        contentlengthremaining = range_length
        try:
            while 1:
                if (
                    contentlengthremaining < 0
                    or contentlengthremaining > self.block_size
                ):
                    readbuffer = fileobj.read(self.block_size)
                else:
                    readbuffer = fileobj.read(contentlengthremaining)
                assert util.is_bytes(readbuffer)
                yield readbuffer
                contentlengthremaining -= len(readbuffer)
                if len(readbuffer) == 0 or contentlengthremaining == 0:
                    break
        finally:
            # yield readbuffer MAY fail with a GeneratorExit error
            # we still need to close the file
            fileobj.close()
        return
