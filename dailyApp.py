# -*- coding:utf-8 -*-
"""
Dec: 网页版的日记本
Created on: 2017.11.30
Author: Iflier
"""
import time
import os.path
from datetime import datetime

import pymysql
import pymysql.cursors
from tornado import web
import tornado.httpserver
from tornado.web import url
from pymongo import MongoClient


clientMon = MongoClient("mongodb://localhost:27017")
clientMy = pymysql.connect(
    host='localhost',
    database='usercount',
    charset='utf8mb4',
    # read_default_file='my.cnf',
    bind_address='127.0.0.1',
    cursorclass=pymysql.cursors.DictCursor
)


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            url(r'/', EnterHandler, name='enterPoint'),
            url(r'/login', LoginHandler, dict(database=clientMy)),
            web.URLSpec(r'/help', HelpHandler, name='help'),
            url(r'/welcome', WelcomeHandler, dict(database=clientMon), name='welcome'),
            web.URLSpec(r'/logout', LogoutHandler, name='logout')
        ]
        settings = {
            "static_path": os.path.join(os.path.dirname(__file__), "static"),
            "template_path": os.path.join(os.path.dirname(__file__), 'templates'),
            "xsrf_cookies": True,
            "debug": True,
            "cookie_secret": "c28b5fa9-874b-4e7b-8f08-8377322d6259",
            "login_url": '/login',
            "static_url_prefix": "/static/"
        }
        tornado.web.Application.__init__(self, handlers=handlers, **settings)


class BaseHandler(tornado.web.RequestHandler):
    """"Handler的基类"""
    def write_error(self, status_code, **kwargs):
        if status_code == 404:
            self.render('404.html')
        elif status_code == 500:
            self.render('500.html')
        elif status_code == 405:
            self.render("verboseNotAllowed.html")            
        else:
            self.write("Error: {0}".format(status_code))


class EnterHandler(BaseHandler):
    def get_current_user(self):
        username = self.get_secure_cookie("username", None)
        print("User name from cookie: {0}".format(username))  # 字节型
        if isinstance(username, bytes):
            return username.decode(encoding='utf-8')
        return None

    @tornado.web.authenticated
    def get(self):
        self.redirect("/welcome")


class LoginHandler(BaseHandler):
    def initialize(self, database):
        self.dbMy = database
    
    def prepare(self):
        self.cursor = self.dbMy.cursor()
    
    def get(self):
        self.render('login.html')
    
    def post(self):
        username = self.get_argument('username', None)
        password = self.get_argument('password', None)
        if username is None or password is None:
            # 排除任何一个为空的情况
            self.render('login.html')
        else:
            sql = "SELECT * FROM dailyuser WHERE username=%s AND password=%s"
            result = self.cursor.execute(sql, (username, password))
            if isinstance(self.cursor.fetchone(), dict):
                # 即查询的用户是存在的
                self.set_secure_cookie('username', username, expires=time.time() + 2 * 60 * 60)
                # cookie有效期2小时
                self.redirect("/welcome", permanent=False)
            else:
                # 用户不存在的话
                self.redirect('/login', permanent=False)
    
    def on_finish(self):
        # 目前仅有post方法会使用光标
        print("[INFO] Closing DB cursor ...")
        self.cursor.close()


class WelcomeHandler(BaseHandler):
    def initialize(self, database):
        self.dbMon = database["Tornado"]
    
    def get_current_user(self):
        # 在该类中，返回的用户名为字符串型
        username = self.get_secure_cookie("username", None)
        if isinstance(username, bytes):
            return username.decode(encoding='utf-8')
        return None
    
    def get(self):
        kwargs = dict()
        username = self.current_user  # 字节型
        if isinstance(username, str):
            Messages = list()
            for doc in self.dbMon.daily.find(projection={"_id": False}):
                if doc:
                    Messages.append(doc)
                else:
                    pass
            kwargs["messages"] = Messages
            kwargs["username"] = username
            self.render("welcome.html", **kwargs)
        else:
            self.redirect("/login")
    
    def post(self):
        username = self.current_user
        print("In post, current user: {0}".format(self.current_user))
        if username is None:
            self.redirect("/login")
        else:
            assert isinstance(username, str), "提交留言时发生错误"
            date = datetime.now().strftime("%Y-%m-%d %A %H:%M:%S")
            message = self.get_argument("leaveMessage", default=None)
            if message:
                insertedResult = self.dbMon.daily.insert_one({"date": date, "message": message})
                print("Inserted ID: {0}".format(insertedResult.inserted_id))
            self.redirect("/welcome")  # 无论如何都会重定向到欢迎页面


class HelpHandler(BaseHandler):
    def get(self):
        self.render('help.html')


class LogoutHandler(BaseHandler):
    """用户登出"""
    def get(self):
        # 清理cookie，重定向到登陆页面
        self.clear_cookie("username")
        # self.set_secure_cookie("username", None)
        self.redirect("/login")


if __name__ == "__main__":
    PORT = 20000
    print("Bind to {} port".format(PORT))
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.bind(PORT)
    http_server.start()
    tornado.ioloop.IOLoop().current().start()
