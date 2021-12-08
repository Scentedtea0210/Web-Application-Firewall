import os
import dash
import socket
import base64
import datetime
import signal
import urllib.parse
import threading
import dash_table
import sd_material_ui
import pandas as pd
import plotly.graph_objs as go
import dash_core_components as dcc
import dash_html_components as html
import dash_bootstrap_components as dbc
from flask import Flask ,render_template,make_response,send_from_directory,request
from werkzeug.utils import secure_filename
from dash.dependencies import Input, Output, State

from Layout import *
from Core import Request
from Log import LogController
from Configuration import Configuration

Log = LogController(Configuration().SetLogPath())
DataSet = Log.ReadALL()
Log.close()

Possible = ['sqli','xss','valid']

def ReloadDataset():
    Log = LogController(Configuration().SetLogPath())
    global DataSet
    DataSet = Log.ReadALL()
    Log.close()

def configure_columns(name):
    if name != 'Location':
        config = {'name': name, 'id': name}
    else:
        config = {'name':'ThreatType','id':'ThreatType'}
    #print(name)
    if name == 'Detail':
        config['presentation'] = 'markdown'
    return config

def Modify(data):
    if data == None:
        return data
    data = data.strip().split(':')[0]
    return data

def CheckOUT(data):
    if data == None:
        return data
    return data.strip().split(':')[0]

def configure_data(df):
    df['Location'] = df['Location'].apply(Modify)
    Columns = {'Location':'ThreatType'}
    df.rename(columns=Columns,inplace=True)
    return df.to_dict('records')

def Generate_Table(df,label,TimeStampFilter):
    df = df.loc[:,('ID','Timestamp','SourceIP','Location','Detail')]
    df['ID'] = df['ID'].astype('str')
    Value = {'SourceIP':'UNKNOWN','Location':'None'}
    df.fillna(value=Value,inplace=True)
    if label == None:
        pass
    elif label == 'valid':
        df = df[df['Location'] == 'None']
    elif label == 'xss' or label == 'sqli':
        df = df[df['Location'].apply(lambda x:x.strip().split(':')[0]) == label]

    if TimeStampFilter == '':
        pass
    else:
        df = df[df['Timestamp'].apply(lambda x:x.split(' ')[0])==TimeStampFilter]

    return dash_table.DataTable(
            id = 'data_table',
            columns=[configure_columns(i) for i in df.columns],
            data= configure_data(df),
            style_cell={
            'overflow': 'hidden',
            'textOverflow': 'ellipsis',
            'maxWidth': 0,
            },
            page_action = "native",
            page_current = 0,
            page_size = 5,
            filter_action = 'native',
            cell_selectable = False
)

def DrawOccupation(Dataset):
    df = Dataset
    X = ['sqli','xss','valid']
    Y = [0,0,0]
    for index,data in df.iterrows():
        if data['Location'] == None:
            Y[2] = Y[2]+1
        elif data['Location'].strip().split(':')[0] == 'xss':
            Y[1]= Y[1]+1
        else:
            Y[0] = Y[0]+1
    trace = [go.Pie(labels=X, values=Y, textposition='inside', textinfo='percent+label')]
    layout = go.Layout()
    fig = go.Figure(data=trace, layout=layout)
    return fig

def get_list(date):
    return datetime.datetime.strptime(date, "%Y-%m-%d").timestamp()

def GetHourParam(df):
    X = []
    for index,data in df.iterrows():
        X.append(data['Timestamp'].split()[0])

    X = list(set(X))
    X = sorted(X, key=lambda date: get_list(date))

    Sqli = [0]*len(X)
    Xss = [0]*len(X)
    Valid = [0]*len(X)

    for index,data in df.iterrows():
        ind = X.index(data['Timestamp'].split()[0])
        if data['Location'] == None:
            Valid[ind] = Valid[ind] + 1
        elif data['Location'].strip().split(':')[0] == 'xss':
            Xss[ind] = Xss[ind] + 1
        elif data['Location'].strip().split(':')[0] == 'sqli':
            Sqli[ind] = Sqli[ind] + 1
    return X,Sqli,Xss,Valid

def DrawStatistic(DataSet):
    df = DataSet
    X, Sqli, Xss, Valid = GetHourParam(df)
    Trace1 = go.Bar(x=X,y=Sqli,hoverinfo='all',name='sqli')
    Trace2 = go.Bar(x=X,y=Xss,hoverinfo='all',name='xss')
    Trace3 = go.Bar(x=X,y=Valid,hoverinfo='all',name='valid')

    trace = [Trace1,Trace2,Trace3]
    layout = {
        'barmode':'group',
    }
    fig = go.Figure(data = trace,layout=layout)
    return fig

def DrawDistrub(DataSet):
    df = DataSet
    X, Sqli, Xss, Valid = GetHourParam(df)
    Trace1 = go.Scatter(x=X, y=Sqli, hoverinfo='all', name='sqli')
    Trace2 = go.Scatter(x=X, y=Xss, hoverinfo='all', name='xss')
    Trace3 = go.Scatter(x=X, y=Valid, hoverinfo='all', name='valid')
    trace = [Trace1, Trace2, Trace3]
    layout = go.Layout()
    fig = go.Figure(data=trace, layout=layout)
    return fig

def main():
    external_stylesheets = ['/css/bootstrap.min.css']
    server = Flask(__name__)
    app = dash.Dash(__name__, external_stylesheets=external_stylesheets, server=server)
    app.config.suppress_callback_exceptions = True
    app.layout =Layout()
    @app.callback(Output('Main Window','children'),[Input('Url','pathname')])
    def Render_page_content(pathname):
        if pathname=='/':
            return HtmlInformation()
        elif pathname=='/Configuration':
            return HtmlConfiguration()
        elif pathname=='/Analysis':
            ReloadDataset()
            return HtmlAnalysis()
        elif pathname=='/Setting':
            return HtmlSetting()

    @app.callback(Output('Check out Dialog','displayed'),[Input('DownloadButton','n_clicks')])
    def DownloadConfiguration(n_clicks):
        if n_clicks != None:
            return True
        else:
            return False

    @app.callback(Output('AttackGraph','figure'),[Input('DropdownGraph','value')])
    def UpdateGraph(Dropdown_Value):
        if Dropdown_Value == 'Occupation':
            fig = DrawOccupation(DataSet)
        if Dropdown_Value == 'Statistic':
            fig = DrawStatistic(DataSet)
        if Dropdown_Value =='Distribution':
            fig = DrawDistrub(DataSet)
        return fig

    @app.callback(
        Output('SaveConfirm-Dialog','displayed'),
        [
            Input('WebServerIP-Input','value'),
            Input('WebServerPort-Input','value'),
            Input('Model-Dropdown','value'),
            Input('FirewallIP-Input','value'),
            Input('FirewallPort-Input','value'),
            Input('GUI-Dropdown','value'),
            Input('LogSystem-Dropdown','value'),
            Input('DatabasePath-Input','value'),
            Input('MachineLearningCore-Dropdown','value'),
            Input('Save','n_clicks'),
        ]
    )
    def SaveSetting(WebServerIP,WebServerPort,Model,FirewallIP,FirewallPort,GUI,LogSystem,DatabasePath,MachineLearningCore,n_clicks):
        #print(n_clicks)
        if n_clicks != None and n_clicks!=0:
            Config.SaveGUI(WebServerIP,WebServerPort,Model,FirewallIP,FirewallPort,GUI,LogSystem,DatabasePath,MachineLearningCore)
            #ReloadLayoutConfig()
            return True
        return False

    @app.callback(
        Output('Save','n_clicks'),
        [
            Input('WebServerIP-Input', 'value'),
            Input('WebServerPort-Input', 'value'),
            Input('Model-Dropdown', 'value'),
            Input('FirewallIP-Input', 'value'),
            Input('FirewallPort-Input', 'value'),
            Input('GUI-Dropdown', 'value'),
            Input('LogSystem-Dropdown', 'value'),
            Input('DatabasePath-Input', 'value'),
            Input('MachineLearningCore-Dropdown', 'value'),
        ]
    )
    def Resetting(WebServerIP,WebServerPort,Model,FirewallIP,FirewallPort,GUI,LogSystem,DatabasePath,MachineLearningCore):
        return 0

    @app.callback(
        Output('UploadConfirm-Dialog','displayed'),
        [Input('Upload','contents')]
    )
    def ModifyConfig(list_of_contents):
        if list_of_contents != None:
            content_type,content_string = list_of_contents.split(',')
            decoded = base64.b64decode(content_string)
            contents = decoded.decode()
            Config_dict = eval(contents)
            Config.Save(Config_dict)
            return True
        return False

    @app.callback(Output('TableData','children'),[Input('AttackGraph','clickData'),Input('ResetButton','n_clicks'),Input('DropdownGraph','value'),Input('interval-component','n_intervals')])
    def Display_Hover_Data(hover,clicks,value,n_intervals):
        #print(n_intervals)
        ctx = dash.callback_context
        if not ctx.triggered:
            component_id = None
        else:
            component_id = ctx.triggered[0]['prop_id'].split('.')[0]
        df = DataSet
        label = None
        TimestampFilter = ''
        if component_id == 'AttackGraph':
            if hover != None and value == 'Occupation':
                label = hover['points'][0]['label']
                TimestampFilter = ''
            if hover != None and value == 'Statistic':
                label = Possible[hover['points'][0]['curveNumber']]
                TimestampFilter = hover['points'][0]['label']
            if hover !=None and value == 'Distribution':
                label = Possible[hover['points'][0]['curveNumber']]
                TimestampFilter = hover['points'][0]['x']
        return Generate_Table(df,label,TimestampFilter)

    @app.callback(Output('RestartConfirm-Dialog','displayed'),
                  [Input('Restart','n_clicks')])
    def Restart_Process(n_clicks):
        if n_clicks == 0:
            return False
        fifo_path = '/tmp/fifo_pi'
        #os.mkfifo(fifo_path)
        with open(fifo_path,'w') as ff:
            ff.write('Restart')
        #os.unlink(fifo_path)
        ReloadLayoutConfig()
        return True

    @app.server.route('/Download')
    def Download():
        return send_from_directory('./','Configuration.json',as_attachment=True)

    @app.server.route('/review/<int:request_id>', methods=['GET', 'POST'])
    def Review_Request(request_id):
        Log = LogController(Configuration().SetLogPath())
        Req = Log.GetRequest(request_id)
        Log.close()
        Req.Url = urllib.parse.unquote_plus(Req.Url)
        return render_template('request.html',id = str(request_id),log=Req)

    Config = Configuration()

    IP,Port = Config.SetFirewall()

    app.run_server(debug=True,host=str(IP),port=8085)


if __name__ == '__main__':
    main()