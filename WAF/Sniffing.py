import json
import requests
import urllib.parse
from urllib import parse
import scapy.all as scapy
from scapy.all import sniff , Raw
from scapy.layers.inet import IP, TCP
from scapy.layers.http import HTTPRequest, HTTP
from scapy.sessions import IPSession, TCPSession
from argparse import ArgumentParser
from flask import Flask,request,redirect,url_for,render_template

from Core import Request
from Classifier import Classifier
from Configuration import Configuration
from Log import LogController
class SniffingProxy():
    def __init__(self):
        self.Config = Configuration()
        self.Port = self.Config.SetSniffPort()
        self.LogStatue,_ = self.Config.SetLogSystem()
        self.Classifier = Classifier()
        self.header_fields = [  'Http_Version',
                                'A_IM',
                                'Accept',
                                'Accept_Charset',
                                'Accept_Datetime',
                                'Accept_Encoding',
                                'Accept_Language',
                                'Access_Control_Request_Headers',
                                'Access_Control_Request_Method',
                                'Authorization',
                                'Cache_Control',
                                'Connection',
                                'Content_Length',
                                'Content_MD5',
                                'Content_Type',
                                'Cookie',
                                'DNT',
                                'Date',
                                'Expect',
                                'Forwarded',
                                'From',
                                'Front_End_Https',
                                'If_Match',
                                'If_Modified_Since',
                                'If_None_Match',
                                'If_Range',
                                'If_Unmodified_Since',
                                'Keep_Alive',
                                'Max_Forwards',
                                'Origin',
                                'Permanent',
                                'Pragma',
                                'Proxy_Authorization',
                                'Proxy_Connection',
                                'Range',
                                'Referer',
                                'Save_Data',
                                'TE',
                                'Upgrade',
                                'Upgrade_Insecure_Requests',
                                'User_Agent',
                                'Via',
                                'Warning',
                                'X_ATT_DeviceId',
                                'X_Correlation_ID',
                                'X_Csrf_Token',
                                'X_Forwarded_For',
                                'X_Forwarded_Host',
                                'X_Forwarded_Proto',
                                'X_Http_Method_Override',
                                'X_Request_ID',
                                'X_Requested_With',
                                'X_UIDH',
                                'X_Wap_Profile']
    def GetHeader(self,packet):
        headers = {}
        headers['Host'] = urllib.parse.unquote(packet[HTTPRequest].Host.decode())
        for field in self.header_fields:
            f = getattr(packet[HTTPRequest], field)
            if f != None and f != 'None':
                headers[field] = f.decode()

        return headers
    def Sniffing(self):
        scapy.packet.bind_layers(TCP,HTTP,dport=int(self.Port))
        scapy.packet.bind_layers(TCP,HTTP,sport=int(self.Port))
        pkgs = sniff(prn=self.Sniffing_Function,filter = 'port ' + str(int(self.Port)) + ' and inbound',session=TCPSession)

    def Sniffing_Function(self,packet):
        if packet.haslayer(HTTPRequest):
            Req = Request()

            if packet.haslayer(IP):
                Req.SourceIP = packet[IP].src
            else:
                Req.SourceIP = 'localhost'

            Req.Method = packet[HTTPRequest].Method.decode()
            Req.Url = urllib.parse.unquote(packet[HTTPRequest].Path.decode())

            '''
            'Host': '192.168.238.129:5000'
            'Http_Version': 'HTTP/1.1'
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
            'Accept_Encoding': 'gzip, deflate'
            'Accept_Language': 'zh-CN,zh;q=0.9,en;q=0.8'
            'Cache_Control': 'max-age=0'
            'Connection': 'keep-alive'
            'Upgrade_Insecure_Requests': '1'
            'User_Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36'}

            '''
            Req.Header = self.GetHeader(packet)
            Req.SetTime()
            try:
                Req.Protocol=Req.Header['Http_Version']
                Req.Header.pop('Http_Version')
            except:
                pass
            if packet.haslayer(Raw):
                Req.Body = packet[Raw].load.decode()
            threat = self.Classifier.Run(Req)
            Req.SetThreat(threat)
            Req.Operation = 'Sniff'
            print(Req.SourceIP,' - - ',Req.Timestamp, '"',Req.Method,' ', Req.Url, ' ', Req.Protocol,'"', Req.Operation)
            if self.LogStatue == True:
                Log = LogController()
                Log.Save(Req)
                Log.close()

class SniffingProxyServer():
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
        if Req.Protocol == 'HTTP/1.1':
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
            Req.Operation = 'Sniff'
            if self.LogStatue == True:
                Log = LogController()
                Log.Save(Req)
                Log.close()

            respone = self.__SendMessage(Req)
            return respone.text

        app.run(host=str(self.FirewallIP), port=int(self.FirewallPort),ssl_context=('./ca/server.crt', './ca/server.key'))

if __name__ =='__main__':
    Sniff = SniffingProxy()
    Sniff.Sniffing()