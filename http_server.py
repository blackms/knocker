#!/usr/bin/env python

import BaseHTTPServer
import subprocess
import re
import argparse
from daemonize import Daemonize
import logging

RESPONSE = "suilennaid"

class MyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    server_version= "MyHandler/1.1"

    def __init__(self, keyword=None):
         super(BaseHTTPServer.BaseHTTPRequestHandler, self).__init__()
         self.keyword = keyword if keyword is not None else "pwd123123123"

    def do_GET(self):
        self.log_message("Command: %s Path: %s Headers: %r" % (self.command, self.path, self.headers.items()))
        self.dumpReq(None)

    def do_POST( self ):
        self.log_message( "Command: %s Path: %s Headers: %r" % (self.command, self.path, self.headers.items()))
        if self.headers.has_key('content-length'):
            length= int( self.headers['content-length'] )
            self.dumpReq(self.rfile.read(length))
        else:
            self.dumpReq(None)

    def checkLogin(self):
        print(self.path.lower())
        rexp = ".*%s.*" % self.keyword
	if (re.match(rexp, self.path.lower())):
            return True
        return False

    def dumpReq(self, formInput=None):
        response = "<html><head></head><body>"
        response += "<p>HTTP Request</p>"
        response += "<p>self.command = <tt>%s</tt></p>" % (self.command)
        response += "<p>self.path = <tt>%s</tt></p>" % (self.path)
	self.addr = self.client_address[0]
        if (self.checkLogin()):
            cmd = 'iptables -nL'
            p = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
            out, err = p.communicate()
            if len([x for x in out.split('\n') if self.addr in x]) is 0:
                cmd = 'iptables -I INPUT -p tcp -s %s --dport 21 -j ACCEPT' % (self.addr)
                p = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
                out, err = p.communicate()
            response += "<p><h1>%s</h1></p>" %s RESPONSE
        response += "</body></html>"
        self.sendPage("text/html", response)

    def sendPage(self, type, body):
        self.send_response(200)
        self.send_header("Content-type", type )
        self.send_header("Content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def httpd(handler_class=MyHandler, server_address=('', 65502),):
    srvr = BaseHTTPServer.HTTPServer(server_address, handler_class)
    srvr.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--daemon', action='store_true')
    parser.add_argument('-p', '--pid', action='store')
    parser.add_argument('-k', '--keyword', action='store')
    p = parser.parse_args()

    pid = "/var/run/knock.pid" if p.pid is None else p.pid
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    fh = logging.FileHandler("/tmp/test.log", "w")
    fh.setLevel(logging.DEBUG)
    logger.addHandler(fh)
    keep_fds = [fh.stream.fileno()]


    if (p.daemon):
        daemon = Daemonize(app="httpd", pid=pid, action=httpd, keep_fds=keep_fds)
        daemon.start()
    else:
        httpd()
