#!/usr/bin/env python

import json
import os

from tornado.escape import utf8
from tornado.ioloop import IOLoop
from tornado.options import define, options, parse_command_line, parse_config_file
from tornado.web import RequestHandler, Application, asynchronous, authenticated, HTTPError

from async_dropbox import DropboxMixin

define('port', default=8888)
define('flagfile', default='config.flags')
define('debug', default=False)
define('cookie_secret', default="3f8c0458deffeb471fc4142c1c0ad232")

# These don't have defaults; see README for details.
define('dropbox_consumer_key')
define('dropbox_consumer_secret')

class BaseHandler(RequestHandler):
    def get_current_user(self):
        if self.get_secure_cookie("user"):
            return json.loads(self.get_secure_cookie("user"))
        else:
            return None

    def get_access_token(self):
        # json turns this into unicode strings, but we need bytes for oauth
        # signatures.
        return dict((utf8(k), utf8(v)) for (k, v) in self.current_user["access_token"].iteritems())

class RootHandler(BaseHandler, DropboxMixin):
    @authenticated
    @asynchronous
    def get(self):
        self.dropbox_request('api', '/1/metadata/sandbox/', self.on_metadata,
                             self.get_access_token(),
                             list="true")
    
    def on_metadata(self, response):
        response.rethrow()
        metadata = json.load(response.buffer)
        self.render("index.html", metadata=metadata)

class DeleteHandler(BaseHandler, DropboxMixin):
    @authenticated
    @asynchronous
    def get(self):
        # This really shouldn't be a GET, but the point is to demonstrate
        # the dropbox api rather than demonstrate good web practices...
        self.dropbox_request(
            'api', '/1/fileops/delete', self.on_delete,
            self.get_access_token(),
            post_args=dict(
                root='sandbox',
                path=self.get_argument('path')))

    def on_delete(self, response):
        response.rethrow()
        self.redirect('/')

class CreateHandler(BaseHandler, DropboxMixin):
    @authenticated
    @asynchronous
    def post(self):
        self.dropbox_request(
            'api-content',
            '/1/files_put/sandbox/%s' % self.get_argument('filename'),
            self.on_put_done,
            self.get_access_token(),
            put_body="Hi, I'm a text file!")

    def on_put_done(self, response):
        response.rethrow()
        self.redirect('/')

class DropboxLoginHandler(BaseHandler, DropboxMixin):
    @asynchronous
    def get(self):
        if self.get_argument("oauth_token", None):
            self.get_authenticated_user(self._on_auth)
            return
        self.authorize_redirect(callback_uri=self.request.full_url())

    def _on_auth(self, user):
        if not user:
            raise HTTPError(500, "Dropbox auth failed")
        self.set_secure_cookie("user", json.dumps(user))
        self.redirect('/')

class LogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie("user")
        self.redirect("/")

def main():
    parse_command_line()
    parse_config_file(options.flagfile)

    settings = dict(
        login_url='/login',
        debug=options.debug,
        template_path=os.path.join(os.path.dirname(__file__), 'templates'),
        static_path=os.path.join(os.path.dirname(__file__), 'static'),

        cookie_secret=options.cookie_secret,
        dropbox_consumer_key=options.dropbox_consumer_key,
        dropbox_consumer_secret=options.dropbox_consumer_secret,
        )
    app = Application([
            ('/', RootHandler),
            ('/delete', DeleteHandler),
            ('/create', CreateHandler),
            ('/login', DropboxLoginHandler),
            ('/logout', LogoutHandler),
            ], **settings)
    app.listen(options.port)
    IOLoop.instance().start()

if __name__ == '__main__':
    main()
