#!/usr/bin/env python
# -*-coding:utf-8-*-
# Author: xujianfeng_sx@qiyi.com
# Time  : 2016-06-19

# 1.单独部署时，则需要在proxy-server.conf中的pipeline中加入
# pipeline = catch_errors proxy-logging cache white_list proxy-server
#    [filter:white_list]
#    use = egg:swift#white_list
#
# 2.与keystone混合部署，白名单中的IP则不需要进行鉴权
# pipeline = catch_errors proxy-logging cache authtoken keystoneauth proxy-server
# 需要修改authtoken keystoneauth两个模块对应的源代码，修改__call__函数
#
# 默认读取/etc/swift/white_list文件作为白名单文件：
# 10.153.88.100
# 10.153.88.101
# 每一行代表一个IP
#

import os

from swift.common.swob import Request, HTTPForbidden
from swift.common.utils import get_logger


def get_remote_client(req):
    # remote host for zeus
    client = req.headers.get('x-cluster-client-ip')
    if not client and 'x-forwarded-for' in req.headers:
        # remote host for other lbs
        client = req.headers['x-forwarded-for'].split(',')[0].strip()
    if not client:
        client = req.remote_addr

    # if client ip with port, delete port
    if client is not None and len(client) > 6:
        length = len(client)
        pos = client.rfind(":", length - 6, length)
        if pos > 0:
            client = client[:pos]
    return client


def ip_check(ip):
    if ip is None:
        return False
    q = ip.split('.')
    return len(q) == 4 and len(filter(lambda x: x >= 0 and x <= 255, \
                                      map(int, filter(lambda x: x.isdigit(), q)))) == 4


class WhiteListMiddleware(object):
    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        if conf is None:
            self.conf = {}
        self.white_list_file = self.conf.get('white_list_file', '/etc/swift/white_list')
        self.white_list = None
        self.logger = get_logger(self.conf, log_route='proxy-server')

        self._parse_config_file()

    def __call__(self, env, start_response):
        req = Request(env)
        remote_addr = get_remote_client(req)
        if remote_addr is not None:
            if self.white_list.get(remote_addr, None) is None:
                return HTTPForbidden(request=req)
        return self.app(env, start_response)

    def allow(self, env):
        if self.white_list is not None:
            req = Request(env)
            remote_addr = get_remote_client(req)
            if self.white_list.get(remote_addr, None) is not None:
                return True
        return False

    def is_valid(self):
        return True if self.white_list is not None else False

    def _parse_config_file(self):
        if not os.path.isfile(self.white_list_file):
            self.white_list = None
            self.logger.info("WhiteListMiddleware: white list file not exist, use default authentication")
            return

        try:
            with open(self.white_list_file, 'r') as fp:
                self.white_list = dict()
                for ip in fp:
                    try:
                        if ip is not None:
                            ip = ip.strip("\r\n").strip()
                            if (len(ip) > 0 and ip[0] == "#") or len(ip) == 0:
                                continue
                            if ip_check(ip):
                                self.white_list[ip] = '1'
                            else:
                                self.logger.error("WhiteListMiddleware: Invalid IP %s" % ip)
                    except Exception as ex:
                        self.logger.error("WhiteListMiddleware: read white list file exception: %s", ex)
            if self.white_list and len(self.white_list) == 0:
                self.white_list = None
                self.logger.warning("WhiteListMiddleware: white list file is empty")
        except Exception as ex:
            self.logger.error('WhiteListMiddleware: open white list file exception: %s', ex)
            self.white_list = None
        if self.white_list is not None:
            self.logger.info("WhiteListMiddleware: there are %s IPs allow to access" % len(self.white_list))


class Singleton(type):
    # def __init__(cls, what, bases, dict):
    #     super(Singleton, cls).__init__(what, bases, dict)
    #     cls._instance = None

    def __call__(cls, *args, **kwargs):
        if not hasattr(cls, '_instance'):
            cls._instance = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instance


class WhiteList(object):
    __metaclass__ = Singleton

    def __init__(self, conf):
        self.white_list_middleware = WhiteListMiddleware(None, conf)

    def allow(self, env):
        return self.white_list_middleware.allow(env)

    def is_valid(self):
        return self.white_list_middleware.is_valid()


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def white_list_filter(app):
        return WhiteListMiddleware(app, conf)

    return white_list_filter
