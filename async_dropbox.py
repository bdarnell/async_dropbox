import tornado.auth
import functools
import urllib
from tornado.httpclient import AsyncHTTPClient
import json
import logging

class DropboxMixin(tornado.auth.OAuthMixin):
    """Dropbox OAuth authentication.

    Uses the app settings dropbox_consumer_key and dropbox_consumer_secret.

    Usage::
    
        class DropboxLoginHandler(RequestHandler, DropboxMixin):
            @asynchronous
            def get(self):
                if self.get_argument("oauth_token", None):
                    self.get_authenticated_user(self._on_auth)
                    return
                self.authorize_redirect()

            def _on_auth(self, user):
                if not user:
                    raise tornado.web.HTTPError(500, "Dropbox auth failed")
                # save the user using e.g. set_secure_cookie
    """
    _OAUTH_VERSION = "1.0"
    # note www vs api.dropbox.com in authorize url
    _OAUTH_REQUEST_TOKEN_URL = "https://api.dropbox.com/1/oauth/request_token"
    _OAUTH_ACCESS_TOKEN_URL = "https://api.dropbox.com/1/oauth/access_token"
    _OAUTH_AUTHORIZE_URL = "https://www.dropbox.com/1/oauth/authorize"

    def dropbox_request(self, subdomain, path, callback, access_token,
                        post_args=None, put_body=None, **args):
        url = "https://%s.dropbox.com%s" % (subdomain, path)
        if access_token:
            all_args = {}
            all_args.update(args)
            all_args.update(post_args or {})
            assert not (put_body and post_args)
            if put_body is not None:
                method = "PUT"
            elif post_args is not None:
                method = "POST"
            else:
                method = "GET"
            oauth = self._oauth_request_parameters(
                url, access_token, all_args, method=method)
            args.update(oauth)
        if args: url += "?" + urllib.urlencode(args)
        http = AsyncHTTPClient()
        if post_args is not None:
            http.fetch(url, method=method, body=urllib.urlencode(post_args),
                       callback=callback)
        else:
            http.fetch(url, method=method, body=put_body, callback=callback)

    def _oauth_consumer_token(self):
        return dict(
            key=self.settings["dropbox_consumer_key"],
            secret=self.settings["dropbox_consumer_secret"],
            )

    def _oauth_get_user(self, access_token, callback):
        callback(dict(
                access_token=access_token,
                uid=self.get_argument('uid'),
                ))
