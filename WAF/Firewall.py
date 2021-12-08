import os
import sys
import time
import getopt
import socket
import signal
import threading
import datetime
import urllib.parse
from multiprocessing import Process , Pipe,Queue

from Core import Request
from Log import LogController
from Configuration import Configuration
from TransparentProxy import TransparentProxy,TransparentProxyServer
from Sniffing import SniffingProxy,SniffingProxyServer
Config = Configuration()

def restart_program():
  python = sys.executable
  os.execl(python, python, * sys.argv)

def killDashboard():
    cmd = 'sudo lsof -i:8085'
    result = os.popen(cmd)

    str_list = result.read()
    str_list = str_list.splitlines()[1:-1]
    for cell in str_list:
        cmd = 'sudo kill -9 '+cell.split()[1]
        #print(cmd)
        os.system(cmd)

def kill_self():
    str = input()
    if str == 'quit':
        killDashboard()
        if Config.SetModel() == 'Transparent':
            Config.DeleteIptable()
        if Config.SetModel() == 'Sniffing' and os.listdir('./ca'):
            Config.DeleteSniffingIptable()
        os.kill(os.getpid(),signal.SIGKILL)
    if str == 'restart':
        restart_program()
def RecvSignal():
    fifo_path = '/tmp/fifo_pi'
    try:
        os.mkfifo(fifo_path)
    except:
        pass

    while True:
        with open(fifo_path,'r') as ff:
            if ff.read() == 'Restart':
                os.unlink(fifo_path)
                if Config.SetModel() == 'Transparent':
                    Config.DeleteIptable()
                print('Firewall System will be restarted...')
                #Config.Reload()
                restart_program()

def AanalysisParam():
    Param = {}
    Setting = True
    option , argv = getopt.getopt((sys.argv[1:]),"GLM:C:",["json","GUI","Log","Model=","WebServerIP=","WebServerPort=","FirewallIP=","FirewallPort=","Core="])
    for key , value in option:
        if key in ('-G','--GUI'):
            Param['GUI'] = 'True'
        if key in ('-L','--Log'):
            Param['LogSystem'] = 'True'
        if key in ('--Model'):
            Param['Model'] = value
        if key in ('--WebServerIP'):
            Param['WebServerIP'] = value
        if key in ('--WebServerPort'):
            Param['WebServerPort'] = value
        if key in ('--FirewallIP'):
            Param['FirewallIP'] = value
        if key in ('--FirewallPort'):
            Param['FirewallPort'] = value
        if key in ('--Core'):
            Param['MachineLearningCore'] = value
        if key in ('--json'):
            Setting = False
    if not "GUI" in Param.keys():
        Param['GUI'] = 'False'
    if not 'Log' in Param.keys():
        Param['LogSystem'] = 'False'
    return Setting,Param

def SaveData(Req):
    Log = LogController()
    Log.Save(Req)
    Log.close()

def StartTransparentProxy():
    _,_,FirewallIP,FirewallPort = Config.SetTransparentConfig()
    SOCK_ADDR = (FirewallIP,FirewallPort)
    global sock
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    sock.bind(SOCK_ADDR)
    proxy = TransparentProxy(sock)
    while True:
        sock.listen(5)
        Req = proxy.Proxy()
        if Req.Url == '' and Req.Header=={} and Req.Body == '':
            continue

        if Req.Timestamp=='' :
            Req.SetTime()

        Statue,_ = Config.SetLogSystem()

        if Statue==True:
            T1 = threading.Thread(target=SaveData,args=(Req,))
            T1.start()

        Req.Show()

def main():

    Setting,Param = AanalysisParam()
    if Setting ==True:
        Config.Save(Param)
    print('Welcome Machine Learning Based Web Firewall V1.1...')
    print('Firewall System has started...')
    t1 = threading.Thread(target=RecvSignal)
    t1.start()
    t2 = threading.Thread(target=kill_self)
    t2.start()
    Model = Config.SetModel()
    if Model == 'Transparent':
        print('Firewall System has been set in Transparent Proxy...')
        Config.SetUP()
        #StartTransparentProxy()
        Server = TransparentProxyServer()
        Server.proxy()
    if Model == 'Sniffing':
        print('Firewall System has been set in Sniffing Proxy...')
        if not os.listdir("./ca"):
            Sniff = SniffingProxy()
            Sniff.Sniffing()
        else:
            Config.SetUPSniffing()
            Server = SniffingProxyServer()
            Server.proxy()
if __name__ == '__main__':
    main()
