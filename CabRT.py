"""============================================================================
INFORMATION ABOUT CODE         Coding:
===============================================================================
Basic Authentication with Tornado and Redis DB

Author: Prajinkya Pimpalghare
Date: 25-March-2018
Version: 1.0
============================================================================"""
import tornado.httpserver
import tornado.ioloop
import tornado.web
import tornado.options
import os.path
import redis
import json
import hashlib
from tornado.options import define, options

define("port", default=8888, help="run on the given port", type=int)


class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        return self.get_secure_cookie("user")


class MainHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        self.render('index.html')


class LoginHandler(BaseHandler):
    @tornado.gen.coroutine
    def get(self):
        incorrect = self.get_secure_cookie("incorrect")
        if incorrect and int(incorrect) > 20:
            self.write('<center>blocked</center>')
            return
        self.render('main.html')

    @tornado.gen.coroutine
    def post(self):
        incorrect = self.get_secure_cookie("incorrect")
        if incorrect and int(incorrect) > 20:
            self.write('<center>blocked</center>')
            return
        getoption = tornado.escape.xhtml_escape(self.get_argument("option"))
        if getoption == "CLIENTLOGIN":
            self.client_login()
            return
        if getoption == "DRIVERLOGIN":
            self.driver_login()
            return
        if getoption == "DRIVERSIGNUP":
            self.driver_signup()
            return
        if getoption == "CLIENTSIGNUP":
            self.client_signup()
            return

    def authentication_against_database(self,username,password,type):
        authentication_data = hashlib.sha256(json.dumps({"token": password, "type": type}).encode())
        if redis_server.get(username).decode() == authentication_data.hexdigest():
            return True
        else:
            incorrect = self.get_secure_cookie("incorrect") or 0
            increased = str(int(incorrect) + 1)
            self.set_secure_cookie("incorrect", increased)
            self.write("""<center>
                            Something Wrong With Your Data (%s)<br />
                            <a href="/">Go Home</a>
                          </center>""" % increased)

    def client_login(self):
        get_username = tornado.escape.xhtml_escape(self.get_argument("username"))
        get_password = tornado.escape.xhtml_escape(self.get_argument("password"))
        if self.authentication_against_database(get_username,get_password,"client"):
            self.set_secure_cookie("user", self.get_argument("username"))
            self.set_secure_cookie("incorrect", "0")
            self.redirect(self.reverse_url("client"))

    def driver_login(self):
        get_username = tornado.escape.xhtml_escape(self.get_argument("username"))
        get_password = tornado.escape.xhtml_escape(self.get_argument("password"))
        if self.authentication_against_database(get_username, get_password,"driver"):
            self.set_secure_cookie("user", self.get_argument("username"))
            self.set_secure_cookie("incorrect", "0")
            self.redirect(self.reverse_url("driver"))

    def client_signup(self):
        get_email_address = tornado.escape.xhtml_escape(self.get_argument("email"))
        if not self.existing_user_check(get_email_address):
            get_password = tornado.escape.xhtml_escape(self.get_argument("password"))
            data = hashlib.sha256(json.dumps({"token": get_password, "type": "client"}).encode())
            redis_server.set(str(get_email_address), data.hexdigest())
            self.set_secure_cookie("user", get_email_address)
            self.set_secure_cookie("incorrect", "0")
            self.redirect(self.reverse_url("signup"))
        else:
            incorrect = self.get_secure_cookie("incorrect") or 0
            increased = str(int(incorrect) + 1)
            self.set_secure_cookie("incorrect", increased)
            self.write("""<center>
                        User Already Exist (%s)<br />
                        <a href="/">Go Home</a>
                        </center>""" % increased)

    def driver_signup(self):
        get_email_address = tornado.escape.xhtml_escape(self.get_argument("email"))
        if not self.existing_user_check(get_email_address):
            get_password = tornado.escape.xhtml_escape(self.get_argument("password"))
            data = hashlib.sha256(json.dumps({"token":get_password,"type":"driver"}).encode())
            redis_server.set(str(get_email_address),data)
            self.set_secure_cookie("user", get_email_address)
            self.set_secure_cookie("incorrect", "0")
            self.redirect(self.reverse_url("signup"))
        else:
            incorrect = self.get_secure_cookie("incorrect") or 0
            increased = str(int(incorrect) + 1)
            self.set_secure_cookie("incorrect", increased)
            self.write("""<center>
                                    User Already Exist (%s)<br />
                                    <a href="/">Go Home</a>
                                    </center>""" % increased)

    def existing_user_check(self,user):
        if redis_server.get(user):
            return True
        else:
            return False


class ClientHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        self.render('client.html')


class DriverHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        self.render('driver.html')


class SignupHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        self.render('signup.html')


class LogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie("user")
        self.redirect(self.get_argument("next", self.reverse_url("main")))


class Application(tornado.web.Application):
    def __init__(self):
        base_dir = os.path.dirname(__file__)
        settings = {
            "cookie_secret": "bZJc2sWbQLKos6GkHn/VB9oXwQt8S0R0kRvJ5/xJ89E=",
            "login_url": "/main",
            'template_path': os.path.join(base_dir, "templates"),
            'static_path': os.path.join(base_dir, "static"),
            'debug': True,
            "xsrf_cookies": True,
        }

        tornado.web.Application.__init__(self, [
            tornado.web.url(r"/", MainHandler, name="main"),
            tornado.web.url(r'/main', LoginHandler, name="login"),
            tornado.web.url(r'/driver', DriverHandler, name="driver"),
            tornado.web.url(r'/client', ClientHandler, name="client"),
            tornado.web.url(r'/signup', SignupHandler, name="signup"),
            tornado.web.url(r'/logout', LogoutHandler, name="logout"),
        ], **settings)


def main():
    tornado.options.parse_command_line()
    Application().listen(options.port)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    redis_server = redis.Redis("localhost")
    main()
