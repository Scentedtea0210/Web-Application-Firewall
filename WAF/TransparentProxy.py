import os
import socket
import json
import requests
import datetime
import threading
from urllib import parse
from flask import Flask,request,redirect,url_for,render_template

from Core import Request
from Classifier import Classifier
from Configuration import Configuration
from Log import LogController
class TransparentProxy():

    def __init__(self,Sock):
        self.Config = Configuration()
        self.ServerIP,self.ServerPort,self.FirewallIP,self.FirewallPort = self.Config.SetTransparentConfig()
        self.Sock = Sock

    def ParseThreat(self,Req):
        if not isinstance(Req, Request):
            raise TypeError("Object should be a Request")

        Model = Classifier()
        return Model.Run(Req)

    def __ParseUrl(self,Url):
        Detail = parse.urlparse(Url)
        Param = Detail.query
        Param = Param.split("&")
        Params = {}
        for p in Param:
            if p == "":
                continue
            label, value = p.split('=')
            label = label.strip()
            value = value.strip()
            Params[label] = value
        return Params

    def __ParseBody(self,Body):
        Body = Body.split('\r\n')
        Params = {}
        for Each in Body:
            if Each == "":
                continue
            Param = Each.split("&")
            # print("Param=",Param)
            for p in Param:
                label, value = p.split("=")
                label = label.strip()
                value = value.strip()
                Params[label] = value
        return Params

    def __GenerateUrl(self,Req):
        Host = Req.Header['Host']
        if Req.Protocol == 'HTTP/1.1':
            Url = 'http://' + Host + Req.Url
        return Url

    def __SendMessage(self,Req):
        Cookies = ''
        if "cookies" in Req.Header:
            Cookies = Req.Header['Cookies']
            Req.Header.pop('cookies')
        BodyParam = self.__ParseBody(Req.Body)

        UrlParam = self.__ParseUrl(Req.Url)

        Method = Req.Method.lower()

        Url = self.__GenerateUrl(Req)

        Respone = requests.request(Method,Url,params=UrlParam,data=BodyParam,cookies=Cookies)

        return Respone

    def __GenerateRespone(self,Respone,Req):
        Protocol = Req.Protocol + ' '
        Statue = Respone.status_code
        Explain = ' OK'
        ResponeLine = Protocol + str(Statue) + Explain + '\r\n'
        ResponeBody = Respone.text + '\r\nTransparent'

        ResponeHeader = ""
        Headers = Respone.headers
        for index, content in Headers.items():
            if index == "Content-Length":
                content = str(len(ResponeBody))
            ResponeHeader = ResponeHeader + index + ": " + content + "\r\n"

        ResponeHeader = ResponeHeader + "\r\n"

        return ResponeLine + ResponeHeader + ResponeBody

    def __GenerateSecurityRespone(self,Req):

        ResponeLine = "HTTP/1.1 200 OK\r\n"
        ResponeBody = "Attack Detected!!!<br/>"
        AttackResult = ""
        for key,value in Req.ThreatType.items():
            Location,value = value.split(':')
            Attack = Location + '->' + value + ':' + key

            AttackResult = AttackResult + '<xmp>' + Attack +'</xmp>'
        ResponeBody = ResponeBody + AttackResult

        GMT_FORMAT = '%a, %d %b %Y %H:%M:%S GMT'
        date = datetime.datetime.utcnow().strftime(GMT_FORMAT)
        ResponHeaders = "Content-Type: text/html; charset=utf-8\r\nContent-Length: " + str(len(ResponeBody)) + "\r\nServer: WebFirewall/1.0 Python/3.7.9\r\nDate: " + str(date) + "\r\n\r\n"

        Respone = ResponeLine + ResponHeaders +ResponeBody

        return Respone

    def Proxy(self):
        connection,addr = self.Sock.accept()

        SourceIP = addr[0]
        Data = connection.recv(2048)

        if len(Data) == 0:
            return Request(Url='' , Header='', Body='')
        #print('Recv!')
        Req = Request()
        Req.ParseRequest(Data)
        Req.ParaseSourceIP(SourceIP)
        Req.ThreatType = self.ParseThreat(Req)

        if not Req.ThreatType:
            Respone = self.__SendMessage(Req)

            Respone = self.__GenerateRespone(Respone,Req)

            connection.send(Respone.encode())
        else:

            Rspone = self.__GenerateSecurityRespone(Req)

            connection.send(Rspone.encode())

        return Req

class TransparentProxyServer():
    def __init__(self):
        self.Config = Configuration()
        self.ServerIP, self.ServerPort, self.FirewallIP, self.FirewallPort = self.Config.SetTransparentConfig()
        self.LogStatue,self.LogPath = self.Config.SetLogSystem()
    def ParseThreat(self,Req):
        if not isinstance(Req, Request):
            raise TypeError("Object should be a Request")

        Model = Classifier()
        return Model.Run(Req)

    def __ParseUrl(self, Url):
        Detail = parse.urlparse(Url)
        Param = Detail.query
        Param = Param.split("&")
        Params = {}
        for p in Param:
            if p == "":
                continue
            label, value = p.split('=',1)
            label = label.strip()
            value = value.strip()
            Params[label] = value
        return Params

    def __ParseBody(self, Body):
        Body = Body.split('\r\n')
        Params = {}
        for Each in Body:
            if Each == "":
                continue
            Param = Each.split("&")
            # print("Param=",Param)
            for p in Param:
                label, value = p.split("=")
                label = label.strip()
                value = value.strip()
                Params[label] = value
        return Params

    def __GenerateUrl(self, Req):
        Host = Req.Header['Host']
        if not os.listdir("./ca"):
            Url = 'http://' + Host + Req.Url
        else:
            Url = 'https://' + Host + Req.Url
        return Url

    def __SendMessage(self,Req):
        Cookies = ''
        if "cookies" in Req.Header:
            Cookies = Req.Header['Cookies']
            Req.Header.pop('cookies')
        BodyParam = self.__ParseBody(Req.Body)

        UrlParam = self.__ParseUrl(Req.Url)

        Method = Req.Method.lower()

        Url = self.__GenerateUrl(Req)

        Respone = requests.request(Method,Url,verify=False,params=UrlParam,data=BodyParam,cookies=Cookies)

        return Respone

    def proxy(self):
        app = Flask(__name__)

        @app.before_request
        def GetData():
            Req = Request(ID='',Timestamp='',SourceIP ='',Method = '',Url = '',Protocol='',Header={},Body='',ThreatType={})
            Req.SetTime()
            from builtins import str
            Req.SourceIP = str(request.remote_addr)
            Req.Method = str(request.method)
            try:
                parm ='?'+str(request.url).split('?')[1]
            except:
                parm=''
            Req.Url = str(request.path) + parm
            Req.Header = Req.Str2Dic(str(request.headers))
            json_str = json.dumps(request.form)
            data = json.loads(json_str)
            str = ""
            for key,value in data.items():
                str = str + key + "=" + value + "&"
            Req.Body = str[0:-1]
            Req.ThreatType = self.ParseThreat(Req)
            if Req.ThreatType == {}:
                Req.Operation = 'Pass'
            else:
                Req.Operation = 'Intercept'
            if self.LogStatue == True:
                Log = LogController()
                Log.Save(Req)
                Log.close()
            if Req.ThreatType == {}:
                respone = self.__SendMessage(Req)
                return respone.text
            else:
                return render_template('Attack.html',log=Req)

        if not os.listdir("./ca"):
            app.run(host=str(self.FirewallIP), port=int(self.FirewallPort))
        else:
            app.run(host=str(self.FirewallIP), port=int(self.FirewallPort),ssl_context=('./ca/server.crt', './ca/server.key'))

if __name__=='__main__':
    server = TransparentProxyServer()
    server.proxy()
