from sklearn.externals import joblib
from Core import Request
import urllib.parse
import json

from Configuration import Configuration
# 此类用于机器学习预测Request
class Classifier(object):

    def __init__(self):
        self.Config = Configuration()
        self.ModelPath = self.Config.SetClassifierCore()
        self.Model = joblib.load(self.ModelPath)
        self.Parameters = []
        self.Location = []
        self.RequestParameters = []
        self.BodyParameters = []

    def __standard(self,Content):
        Content = str(Content)
        while (Content != urllib.parse.unquote_plus(Content)):
            Content = urllib.parse.unquote_plus(Content)

        Content = Content.strip()
        Content = ' '.join(Content.splitlines())
        Content = Content.strip()
        Content = ' '.join(Content.split())

        Content = Content.lower()

        return Content

    def __not_valid(self,parameter):
        return parameter != None and parameter != ''

    def __AnalysisHttp(self,Req):
        if not isinstance(Req,Request):
            raise TypeError("Object should be a Request")

        RequestParameters = {}
        BodyParameters = {}

        if self.__not_valid(Req.Url):
            self.Parameters.append(self.__standard(Req.Url))
            self.Location.append('Request')
            RequestParameters = urllib.parse.parse_qs(self.__standard(Req.Url))

        if self.__not_valid(Req.Body):
            self.Parameters.append(self.__standard(Req.Body))
            self.Location.append('Body')

            BodyParameters = urllib.parse.parse_qs(self.__standard(Req.Body))
            if len(BodyParameters) == 0:
                try:
                    BodyParameters = json.loads(self.__standard(Req.Body))
                    BodyParameters = urllib.parse.parse_qs(self.__standard(Req.Body))
                except:
                    pass

        for key,value in RequestParameters.items():
            for cell in value:
                self.RequestParameters.append(cell)

        for key,value in BodyParameters.items():
            if isinstance(value,list):
                for cell in value:
                    self.BodyParameters.append(cell)
            else:
                self.BodyParameters.append(cell)

    def Run(self,Req):
        self.__AnalysisHttp(Req)

        Threat = {}

        if len(self.RequestParameters)!= 0:
            Result = self.Model.predict(self.RequestParameters)

            for key,value in enumerate(Result):
                if value != 'valid':
                    Threat[self.RequestParameters[key]] = 'Request: '+value

        if len(self.BodyParameters) != 0:
            Result = self.Model.predict(self.BodyParameters)
            for key,value in enumerate(Result):
                if value != 'valid':
                    Threat[self.BodyParameters[key]] = 'Body: ' + value
        return Threat

def main():
    req = Request()
    req.Url = '/GetTest?test=or 1 = 1a'
    req.Body = 'test=1\' and ascii(substr(database(),1,1))>114'
    result = Classifier().Run(req)
    print(result)
if __name__=='__main__':
    main()