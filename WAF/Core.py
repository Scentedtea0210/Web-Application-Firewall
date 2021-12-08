import json
import datetime

class Request(object):
    # 用于保存Request请求的类 核心类
    def __init__(self , ID='',Timestamp='',SourceIP ='',Method = '',Url = '',Protocol='',Header={},Body='',ThreatType={},Operation=''):
        #ID 记录Request序号，Timestamp 记录时间戳，SourceIP 记录请求源，Method 记录请求方法，Url 记录访问主机地址（包含Get参数），Protocol 记录请求协议版本，Header 记录请求头，Body 记录请求体，ThreatType 记录攻击类型与位置
        #ID 字符串类型， Timestamp 字符串类型， SoureceIP 字符串类型，Method 字符串类型，Url 字符串类型，Protocol 字符串类型，Header 字典类型，Body 字符串类型，ThreatType 字典类型
        self.ID = ID
        self.Timestamp = Timestamp
        self.SourceIP = SourceIP
        self.Method = Method
        self.Url = Url
        self.Protocol = Protocol
        self.Header = Header
        self.Body = Body
        # ThreatType 记录方式为{位置：攻击方式} 以防止出现key相同
        self.ThreatType = ThreatType
        self.Operation = ''
    #Header和ThreatType 字典类型转字符串类型
    def Dic2Str(self,Dic):
        if not isinstance(Dic,dict):
            raise TypeError("Object should be a DICT")

        Str = ""
        for key,value in Dic.items():
            Str = Str + key + ": " + value + "\r\n"

        return Str

    # Header和ThreatType 字符串类型转字典类型
    def Str2Dic(self,Str):
        if not isinstance(Str,str):
            raise TypeError("Object should be a String")

        Dic = {}
        for Cell in Str.split("\r\n"):
            if Cell == '':
                continue
            key,value = Cell.split(": ")
            Dic[key] = value

        return Dic

    # 获取完整HTTP请求报文内容
    def GetRequest(self):
        ReqeustLine = self.Method + " " + self.Url + " " + self.Protocol + "\r\n"

        HeaderLine = self.Dic2Str(self.Header)

        SpaceLine = "\r\n"

        BodyLine = self.Body

        return ReqeustLine+HeaderLine+SpaceLine+BodyLine

    #根据接受数据保存Request
    def ParseRequest(self,Row):

        Row = Row.decode().splitlines()

        RequestLine = Row[0]
        Space = Row.index('')
        HeaderLine = Row[1:Space]
        BodyLine = Row[Space+1:]

        self.Method , self.Url , self.Protocol = RequestLine.split(' ')

        self.Header = {}
        for Header in HeaderLine:
            key,value = Header.split(': ')
            key = key.strip()
            value = value.strip().lstrip()
            self.Header[key] = value
        for Body in BodyLine:
            self.Body = self.Body + '\r\n' + Body.strip()


    def SetThreat(self,Threat):
        if not isinstance(Threat,dict):
            raise TypeError("Object should be a DICT")

        self.ThreatType = Threat

    def ParaseSourceIP(self,IP):
        self.SourceIP = IP

    def SetTime(self):
        self.Timestamp =datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def Show(self):
        print('Timestamp = ',self.Timestamp)
        print('SourceIP = ',self.SourceIP)
        print('Request = ',self.Method,' ',self.Url,' ',self.Protocol)
        print('Header = ',self.Dic2Str(self.Header))
        print('Body = ',self.Body)
        print('ThreatType= ',self.ThreatType)
        print('Operation=',self.Operation)