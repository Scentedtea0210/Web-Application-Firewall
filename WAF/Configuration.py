import os
import json

class Configuration():

    def __init__(self,Path='./Configuration.json'):
        self.Path = Path
        with open(self.Path,'r',encoding='utf-8') as fp:
            self.Data = json.load(fp)

    def Reload(self):
        with open(self.Path,'r',encoding='utf-8') as fp:
            self.Data = json.load(fp)

    def SetLogPath(self):
        path = self.Data['DatabasePath']
        return path

    def SetClassifierCore(self):
        Core = self.Data['MachineLearningCore']
        return Core

    def SetSniffPort(self):
        Port = self.Data['WebServerPort']
        return Port

    def SetModel(self):
        Model = self.Data['Model']
        return Model

    def SetFirewall(self):
        IP = self.Data['FirewallIP']
        Port = self.Data['FirewallPort']
        return IP,Port

    def SetGui(self):
        Statue = self.Data['GUI']
        if Statue == "True":
            return True
        else:
            return False

    def SetLogSystem(self):
        Statue = self.Data['LogSystem']
        if Statue == "True":
            DbPath = self.Data['DatabasePath']
            return True , DbPath
        else:
            return False , ''

    def SetServerConfig(self):
        IP = self.Data['WebServerIP']
        Port = self.Data['WebServerPort']
        return IP , Port

    def SetTransparentConfig(self):
        ServerIP = self.Data['WebServerIP']
        ServerPort = self.Data['WebServerPort']
        FirewallIP = self.Data['FirewallIP']
        FirewallPort = self.Data['FirewallPort']
        return str(ServerIP),int(ServerPort),str(FirewallIP),int(FirewallPort)

    def SetUP(self):
        if self.Data['Model'] == "Transparent":
            cmd = "iptables -t nat -A PREROUTING -p tcp -m tcp --dport " + str(self.Data['WebServerPort'])+" -j REDIRECT --to-ports "+str(self.Data['FirewallPort'])
            os.system(cmd)
            cmd = "iptables -t filter -A INPUT -s "+str(self.Data['FirewallIP']) + "/32 -p tcp -m tcp --dport "+str(self.Data['WebServerPort']) +" -j ACCEPT"
            os.system(cmd)
            cmd = "iptables -t filter -A INPUT -p tcp -m tcp --dport "+str(self.Data['WebServerPort'])+" -j DROP"
            os.system(cmd)
            cmd = "lsof -i:" + str(self.Data['FirewallPort'])
            result = os.popen(cmd)
            str_list = result.read()
            if len(str_list) != 0:
                pid = str_list.split("\n")[1].split()[1]
                cmd = "kill -9 " + pid
                os.system(cmd)
            print("Transparent Proxy Configuration has been installed....")
    def Save(self,Param):
        for key,value in Param.items():
            self.Data[key] = value
        with open(self.Path,'w') as fp:
            json.dump(self.Data,fp)

    def SaveGUI(self,WebServerIP,WebServerPort,Model,FirewallIP,FirewallPort,GUI,LogSystem,DatabasePath,MachineLearningCore):
        self.Data['WebServerIP'] = WebServerIP
        self.Data['WebServerPort'] = int(WebServerPort)
        self.Data['Model'] = Model
        self.Data['FirewallIP'] = FirewallIP
        self.Data['FirewallPort'] = int(FirewallPort)
        self.Data['LogSystem'] = str(LogSystem)
        self.Data['GUI'] = str(GUI)
        self.Data['DatabasePath'] = str(DatabasePath)
        self.Data['MachineLearningCore'] = '../Model/'+MachineLearningCore+'.joblib'
        with open(self.Path,'w') as fp:
            json.dump(self.Data,fp)


    def DeleteIptable(self):
        if self.Data['Model'] == "Transparent":
            cmd = "iptables -t nat -D PREROUTING -p tcp -m tcp --dport " + str(self.Data['WebServerPort'])+" -j REDIRECT --to-ports "+str(self.Data['FirewallPort'])
            os.system(cmd)
            cmd = "iptables -t filter -D INPUT -s " + str(self.Data['FirewallIP']) + "/32 -p tcp -m tcp --dport " + str(self.Data['WebServerPort']) + " -j ACCEPT"
            os.system(cmd)
            cmd = "iptables -t filter -D INPUT -p tcp -m tcp --dport "+str(self.Data['WebServerPort'])+" -j DROP"
            os.system(cmd)
            print("Transparent Proxy Configuration has been uninstalled....")

    def SetUPSniffing(self):
        if self.Data['Model'] == "Sniffing":
            cmd = "iptables -t nat -A PREROUTING -p tcp -m tcp --dport " + str(self.Data['WebServerPort'])+" -j REDIRECT --to-ports "+str(self.Data['FirewallPort'])
            os.system(cmd)
            cmd = "iptables -t filter -A INPUT -s "+str(self.Data['FirewallIP']) + "/32 -p tcp -m tcp --dport "+str(self.Data['WebServerPort']) +" -j ACCEPT"
            os.system(cmd)
            cmd = "iptables -t filter -A INPUT -p tcp -m tcp --dport "+str(self.Data['WebServerPort'])+" -j DROP"
            os.system(cmd)
            cmd = "lsof -i:" + str(self.Data['FirewallPort'])
            result = os.popen(cmd)
            str_list = result.read()
            if len(str_list) != 0:
                pid = str_list.split("\n")[1].split()[1]
                cmd = "kill -9 " + pid
                os.system(cmd)
            print("Sniffing Proxy for Https Configuration has been installed....")

    def DeleteSniffingIptable(self):
        if self.Data['Model'] == "Sniffing":
            cmd = "iptables -t nat -D PREROUTING -p tcp -m tcp --dport " + str(self.Data['WebServerPort'])+" -j REDIRECT --to-ports "+str(self.Data['FirewallPort'])
            os.system(cmd)
            cmd = "iptables -t filter -D INPUT -s " + str(self.Data['FirewallIP']) + "/32 -p tcp -m tcp --dport " + str(self.Data['WebServerPort']) + " -j ACCEPT"
            os.system(cmd)
            cmd = "iptables -t filter -D INPUT -p tcp -m tcp --dport "+str(self.Data['WebServerPort'])+" -j DROP"
            os.system(cmd)
            print("Sniffing Proxy for Https Configuration has been uninstalled....")
def main():
    Config = Configuration()
    Config.SetUP()
if __name__ == '__main__':
    main()
