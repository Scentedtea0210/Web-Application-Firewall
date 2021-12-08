import os
import sys
import json
import sqlite3
import getopt
import datetime
import urllib.parse
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from Configuration import Configuration
from Core import Request

class LogController(object):
    def __init__(self,path=''):
        self.Config = Configuration()
        _,self.DatasetPath = self.Config.SetLogSystem()
        #print(self.Config.Data['DatabasePath'])
        if path!='':
            self.DatasetPath = path
        #self.DatasetPath = './DataSet.db'
        self.connect = sqlite3.connect(self.DatasetPath)
        self.connect.row_factory = sqlite3.Row
        self.LogID = 0
        self.ThreatID = 0

        try:
            Cursor = self.connect.cursor()
            Sql = '''
                  CREATE TABLE logs (
                  ID INTEGER  PRIMARY KEY,
                  Timestamp   VARCHAR(20),
                  SourceIP    VARCHAR(20),
                  Method      VARCHAR(20),
                  Url         TEXT,
                  Protocol    VARCHAR(20),
                  Header      TEXT,
                  Body        TEXT,
                  Operation   VARCHAR(20)
                  )
                  '''
            Cursor.execute(Sql)
            self.LogID = 0
        except:

            Cursor = self.connect.cursor()
            Sql = 'SELECT COUNT(ID) FROM logs'
            Cursor.execute(Sql)

            Data = Cursor.fetchone()
            self.LogID = Data[0]

        try:
            Cursor = self.connect.cursor()
            Sql = '''
                  CREATE TABLE threats (
                  ID     INTEGER PRIMARY KEY,
                  LogID  INTEGER,
                  ThreatType VARCHAR(20),
                  Location TEXT
                  )
                  '''
            Cursor.execute(Sql)
            self.ThreatID = 0
        except:
            Cursor = self.connect.cursor()
            Sql = 'SELECT COUNT(ID) FROM threats'
            Cursor.execute(Sql)
            self.ThreatID = Cursor.fetchone()[0]

    def Save(self,Req):
        if not isinstance(Req,Request):
            raise  TypeError("Saved data should be a Request!!!")

        if Req.Url.endswith('favicon.ico'):
            return
        Cursor = self.connect.cursor()

        Req.SetTime()
        Req.Url = urllib.parse.unquote_plus(Req.Url)
        Sql = '''
              INSERT INTO logs
              (ID , Timestamp , SourceIP , Method , Url , Protocol , Header , Body , Operation)
              VALUES
              (?  , ? , ? , ? , ? , ? , ? , ? , ?)
              '''
        self.LogID = self.LogID + 1
        Protocol = Req.Protocol
        if Protocol == '':
            Protocol = 'HTTP/1.1'
        Cursor.execute(Sql,(self.LogID , Req.Timestamp , Req.SourceIP , Req.Method ,Req.Url, Protocol , Req.Dic2Str(Req.Header) , Req.Body , Req.Operation))

        Req.ID = Cursor.lastrowid

        try:
            for location , threat in Req.ThreatType.items():
                self.ThreatID = self.ThreatID  + 1
                Threat , Point = threat.strip().split(':')
                Cursor.execute('INSERT INTO threats (ID , LogID , ThreatType , Location) VALUES (? , ? , ? , ?)',(self.ThreatID , Req.ID , Threat , Point+':'+location))
        except:
            pass

        self.connect.commit()

    def __create_entry(self, row):
        entry = dict(row)
        DashIP,_ = self.Config.SetFirewall()
        entry['Detail'] = '[Review](http://'+str(DashIP)+':8085/review/'+str(entry['ID'])+')'

        return entry

    def ReadALL(self):

        Cursor = self.connect.cursor()

        Sql = 'SELECT * FROM logs AS L LEFT JOIN threats AS T ON L.ID = T.LogID'

        Cursor.execute(Sql)

        Result = Cursor.fetchall()

        Data = [self.__create_entry(row) for row in Result]

        return pd.DataFrame(Data)

    def GetRequest(self,ID):

        Cursor = self.connect.cursor()

        Sql = 'SELECT * FROM logs AS L LEFT JOIN threats AS T ON L.ID = T.LogID WHERE L.ID = ?'

        Cursor.execute(Sql,(ID,))

        Result = Cursor.fetchall()
        Req = Request(ID='',Timestamp='',SourceIP ='',Method = '',Url = '',Protocol='',Header={},Body='',ThreatType={})
        if len(Result) != 0:
            Req.Timestamp = str(Result[0]['Timestamp'])
            Req.SourceIP = str(Result[0]['SourceIP'])

            Req.Method = str(Result[0]['Method'])
            Req.Url = str(Result[0]['Url'])
            Req.Protocol = str(Result[0]['Protocol'])

            Req.Header = Req.Str2Dic(Result[0]['Header'])
            Req.Body = str(Result[0]['Body'])
            Req.Operation = str(Result[0]['Operation'])

            if Result[0]['Location'] != None:
                for i in range(len(Result)):
                    Point,Location = str(Result[i]['Location']).split(':')
                    Req.ThreatType[Location] = Point+':'+str(Result[i]['ThreatType'])
        return Req

    def DrawThreatTypeOccupation(self, Data):
        Data['Location'].fillna("None", inplace=True)
        NumSqli = Data[Data['Location'].str.contains('sqli')].shape[0]
        NumXss = Data[Data['Location'].str.contains('xss')].shape[0]
        NumValids = Data.shape[0] - NumXss - NumSqli
        # print(NumeSqli)
        # draw pie
        labels = ["sqli", "xss", "valid"]
        color = ["blue", "green", "red"]
        size = [NumSqli, NumXss, NumValids]
        explode = (0, 0, 0)
        plt.pie(size, explode=explode, colors=color, labels=labels, autopct="%1.1f%%")
        plt.axis('equal')
        plt.legend(loc="upper right", frameon=True, fontsize=8)
        plt.title("Attack Type Occupation")
        return plt

    def DrawThreatTypeNum(self, Data):
        Data['Location'].fillna("None", inplace=True)
        NumSqli = Data[Data['Location'].str.contains('sqli')].shape[0]
        NumXss = Data[Data['Location'].str.contains('xss')].shape[0]
        NumValids = Data.shape[0] - NumXss - NumSqli

        X = ["sqli", "xss", "valid"]
        Y = [NumSqli, NumXss, NumValids]
        color = ["blue", "green", "red"]
        plt.bar(X, Y, width=0.5, color=color)
        plt.yticks(range(1, max(Y) * 2, 2))
        plt.title("Attack Type Statistics")
        for x, y in zip(X, Y):
            plt.text(x, y, '%.0f' % y, ha='center', fontsize=11)
        return plt

    def __get_list(self, date):
        return datetime.datetime.strptime(date, "%Y-%m-%d").timestamp()

    def __GetTimeLabel(self, Times):
        Standard = []
        for id, time in Times.items():
            s = str(time).split(" ")[0]
            Standard.append(s)
        Standard = list(set(Standard))
        Standard = sorted(Standard, key=lambda date: self.__get_list(date))
        return Standard

    def DrawLineChartwithTime(self, Data):
        X = self.__GetTimeLabel(Data["Timestamp"])
        # print(X)
        sqli = [0] * len(X)
        xss = [0] * len(X)
        valid = [0] * len(X)
        Data['Location'].fillna("None", inplace=True)
        for index, row in Data.iterrows():
            if row["Location"] == "None":
                timestamp = row['Timestamp'].split(" ")[0]
                index = X.index(timestamp)
                valid[index] = valid[index] + 1
            if "xss" in row["Location"]:
                timestamp = row['Timestamp'].split(" ")[0]
                index = X.index(timestamp)
                xss[index] = xss[index] + 1
            if "sqli" in row["Location"]:
                timestamp = row['Timestamp'].split(" ")[0]
                index = X.index(timestamp)
                sqli[index] = sqli[index] + 1
        plt.plot(X, sqli, c='blue', label='SQL Injection')
        plt.plot(X, xss, c='red', label='Xss', linestyle='--')
        plt.plot(X, valid, c='green', label='Valid', linestyle='-.')
        plt.scatter(X, sqli, c='blue')
        plt.scatter(X, xss, c='red')
        plt.scatter(X, valid, c='green')
        # plt.legend(loc='best')
        Max = [max(sqli), max(xss), max(valid)]
        top = max(Max)
        plt.yticks(range(0, 2 * top, 2))
        plt.legend(loc="upper right", frameon=True, fontsize=8)
        plt.title("Attack Distribution by " + X[-1])
        for a, b in zip(X, sqli):
            plt.text(a, b, b, ha='center', va='bottom', fontsize=11)
        for a, b in zip(X, xss):
            plt.text(a, b, b, ha='center', va='bottom', fontsize=11)
        for a, b in zip(X, valid):
            plt.text(a, b, b, ha='center', va='bottom', fontsize=11)
        return plt

    def CreateLogPdf(self, path="./"):
        Data = self.ReadALL()
        self.close()

        with PdfPages(path + 'log.pdf') as pdf:
            Numplt = self.DrawThreatTypeNum(Data)
            pdf.savefig()
            Numplt.close()

            Occupationplt = self.DrawThreatTypeOccupation(Data)
            pdf.attach_note("graph two")
            pdf.savefig()
            Occupationplt.close()

            Chartplt = self.DrawLineChartwithTime(Data)
            pdf.attach_note("graph three")
            pdf.savefig()
            Chartplt.close()

    def close(self):
        self.connect.close()

def AanalysisParam():
    CreateLog = False
    Read = False
    id = 0
    option , argv = getopt.getopt((sys.argv[1:]),"L",["all",'id='])
    for key , value in option:
        if key in ('-L'):
            CreateLog = True
        if key in ('--all'):
            Read = True
        if key in ('--id'):
            Read = True
            id = int(value)
    return CreateLog,Read,id

def main():
    Log = LogController()
    CreateLog , Read , id = AanalysisParam()
    if CreateLog == True:
        Log.CreateLogPdf()
    if Read == True:
        if id == 0:
            data = Log.ReadALL()
            Log.close()
            data.to_csv('./data.csv')
        elif id < 0 :
            id = Log.LogID + id + 1
            Req = Log.GetRequest(id)
            Log.close()
            Req.Show()
        else:
            Req = Log.GetRequest(id)
            Req.Show()
            Log.close()


if __name__ == '__main__':
    main()