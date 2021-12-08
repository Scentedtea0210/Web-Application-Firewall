import os
import sys
import dash
import socket
import threading
import dash_table
import sd_material_ui
import plotly.graph_objs as go
import  dash_core_components as dcc
import dash_html_components as html
import dash_bootstrap_components as dbc
from flask import Flask ,render_template

from Configuration import Configuration
Config = Configuration()

def ReloadLayoutConfig():
    Config.Reload()

def Layout():
    DashLayout = html.Div(
        id='Main',
        children=[
            dcc.Location(id='Url'),
            dcc.Interval(
                id = 'interval-component',
                interval=60*60*1000,
                n_intervals=0,
                disabled=False,
            ),
            dcc.ConfirmDialog(
                id='Check out Dialog',
                message='Configuration has been downloading...',
            ),
            dcc.ConfirmDialog(
                id='SaveConfirm-Dialog',
                message='Setting has been saved...',
            ),
            dcc.ConfirmDialog(
                id='RestartConfirm-Dialog',
                message='Firewall Restart Successful...',
            ),
            dcc.ConfirmDialog(
                id='UploadConfirm-Dialog',
                message='Upload Successful...'
            ),
            html.Div(
                id='Header',
                children=html.H1(children='Firewall Dash', style={'font-size': '100px'})
            ),
            html.Div(
                id='Left',
                children=[
                        html.Div(
                            children='Controller Bar',
                            style={
                                'font-size':'40px',
                                'color':'black',
                                'text-align':'center',
                            }
                        ),
                        html.Hr(),
                        dbc.Nav(
                            children=[
                                dbc.NavLink(
                                    id='Information Link',
                                    children=[
                                        html.Div(
                                            id='Information Div',
                                            children='Firewall Information',
                                            style={
                                                'font-size':'20px',
                                                'color':'black',
                                                'text-align':'center',
                                            }
                                        )
                                    ],
                                    href='/',
                                    active='exact',
                                    style={
                                        'width':'100%',
                                        'margin':'10% auto'
                                    }
                                    ),
                                dbc.NavLink(
                                    id='Configuration Link',
                                    children=[
                                        html.Div(
                                            id='Configuration Div',
                                            children='Firewall Configuration',
                                            style={
                                                'font-size': '20px',
                                                'color': 'black',
                                                'text-align': 'center',
                                            }
                                        )
                                    ],
                                    href='/Configuration',
                                    active='exact',
                                    style={
                                        'width': '100%',
                                        'margin': '10% auto'
                                    }
                                ),

                                dbc.NavLink(
                                    id='Analysis Link',
                                    children=[
                                        html.Div(
                                            id='Analysis Div',
                                            children='Request Analysis',
                                            style={
                                                'font-size': '20px',
                                                'color': 'black',
                                                'text-align': 'center',
                                            }
                                        )
                                    ],
                                    href='/Analysis',
                                    active='exact',
                                    style={
                                        'width': '100%',
                                        'margin':'10% auto'
                                    }
                                ),

                                dbc.NavLink(
                                    id='Setting Link',
                                    children=[
                                        html.Div(
                                            id='Setting Div',
                                            children='Firewall Setting',
                                            style={
                                                'font-size': '20px',
                                                'color': 'black',
                                                'text-align': 'center',
                                            }
                                        ),
                                    ],
                                    href='/Setting',
                                    active='exact',
                                    style={
                                        'width': '100%',
                                        'margin':'10% auto'
                                    }
                                )
                            ],
                            pills=True,
                            vertical=True,
                        )
                ],
            ),
            html.Div(
                id='Main Window',
                children=[],
                style={
                    'float':'right',
                    'background-color':'#F5F5F5',
                    'width':'80%',
                    'height':'85%'
                }
            )
        ]
    )
    return DashLayout
def GetFirewallStatus():
    cmd = 'ps -ef |grep Firewall.py'
    Result = os.popen(cmd)
    Strlist = Result.read()
    if not 'python Firewall.py' in Strlist.splitlines()[0]:
        return [
            'Stop',
            html.Div(
                children='',
                style={
                    'width': '10px',
                    'height':'10px',
                    'border-radius': '50%',
                    'background-color': 'Red',
                    'display':'inline-block',
                }
            )
        ]
    else:
        return [
            'Running',
            html.Div(
                children='',
                style={
                    'width': '10px',
                    'height':'10px',
                    'border-radius': '50%',
                    'background-color': 'Green',
                    'display':'inline-block',
                }
            )
        ]
def HtmlInformation():
    Row1 = html.Tr([html.Td('Firewall Version'),html.Td('V1.1')])
    Row4 = html.Tr([html.Td('Python Version'),html.Td('python 3.7.9')])
    Row3 = html.Tr([html.Td('Dashboard Server'),html.Td('Flask 1.1.2')])
    Row5 = html.Tr([html.Td('Author'), html.Td('Corey')])
    Row2 = html.Tr([html.Td('Last Update'), html.Td('2021-4-2')])
    Row6 = html.Tr([html.Td('Firewall Status'),html.Td(children=GetFirewallStatus())])
    TableBody = [html.Tbody([Row1,Row2,Row3,Row4,Row5,Row6])]
    Layout = html.Div(
        children=[
            html.H1(
                children='Machine Learning Based Web Firewall V1.1',
                style={
                    'text-align':'center',
                    'font-size':'50px'
                }
            ),
            html.Br(),
            html.Br(),
            dbc.Table(TableBody, bordered=True)
        ],
        style={
            'font-size': '20px',
            'width':'95%',
            'margin':'5% auto'
        }
    )
    return Layout

def HtmlConfiguration():

    TableHeader = [html.Thead(html.Tr([html.Th('Config'),html.Th('Status')]))]
    IP,Port = Config.SetFirewall()
    RowList = []
    for key,value in dict(Config.Data).items():
        Row = html.Tr([html.Td(key),html.Td(value)])
        RowList.append(Row)
    TableBody = [html.Tbody(RowList)]
    Layout = html.Div(
        children=[
            dbc.Table(TableHeader+TableBody,bordered=True),
            html.Br(),
            dbc.Button(
                id='DownloadButton',
                children=[
                    'Download',
                ],
                href='http://'+str(IP)+':'+'8085'+'/Download',
                style={
                    'font-size':'25px',
                    'float':'right',
                    'margin':'auto',
                },
                type='submit',
            )
        ],
        style={
            'font-size': '20px',
            'width': '95%',
            'margin': '5% auto'
        }
    )
    return Layout
def HtmlAnalysis():
    Layout = [
        html.Div(
            children=[
                dcc.Dropdown(
                    id = 'DropdownGraph',
                    options=[
                        {'label':'Attack Occupation','value':'Occupation'},
                        {'label':'Attack Type Statistic','value':'Statistic'},
                        {'label':'Attack Distribution','value':'Distribution'}
                    ],
                    value='Occupation'
                ),
                dcc.Graph(
                    id='AttackGraph',
                    style={
                        'background-color':'#F5F5F5',
                    }
                )
                    ],
            style={
                'width':'95%',
                'margin':'20px auto',
            }
        ),
        html.Div(
            id = 'TableData',
            style={
                'width':'95%',
                'margin':'0px auto',
            }
        ),
        html.Div(
            id='ResetButtonDiv',
            children=[
                dbc.Button(
                    id = 'ResetButton',
                    children='Clear Filters',
                    n_clicks=0.
                )
            ],
            style={
                'margin':'20px 25px',
            }
        )
    ]
    return Layout

def HtmlSetting():
    TableHeader = [html.Thead(html.Tr([html.Th('Config'), html.Th('Setting')]))]
    WebServerIP , WebServerPort , FirewallIP , FirewallPort = Config.SetTransparentConfig()
    RowList = []
    #WebServerIP
    Row = html.Tr(
        [
            html.Td('WebServerIP'),
            dbc.Input(
                id='WebServerIP-Input',
                placeholder=str(WebServerIP),
                value=str(WebServerIP),
                style={
                    'width':'100.1%',
                    'height':'43px',
                    'font-size':'20px'
                },

            )
        ]

    )
    RowList.append(Row)

    #WebServerPort
    Row = html.Tr(
        [
            html.Td('WebServerPort'),
            dcc.Input(
                id='WebServerPort-Input',
                placeholder=int(WebServerPort),
                value=int(WebServerPort),
                type='number',
                min=1,
                max=65535,
                style={
                    'width':'100.1%',
                    'height':'43px',
                    'font-size':'20px',
                }
            ),
        ]
    )
    RowList.append(Row),

    #Model
    Row = html.Tr(
        [
            html.Td('Model'),
            dcc.Dropdown(
                id='Model-Dropdown',
                options=[
                    {'label': 'Transparent', 'value': 'Transparent'},
                    {'label': 'Sniffing', 'value': 'Sniffing'},
                    {'label': 'None', 'value': 'None'},
                ],
                value=Config.SetModel(),
                style={
                    'left':'-5px',
                    'top':'-5px',
                    'margin':'0px 0px',
                    'width':'101%',
                    'height':'43px',
                    'background-color':'#F5F5F5',
                    'font-size': '20px',
                }

            )
        ]
    )
    RowList.append(Row)

    # FirewallIP
    Row = html.Tr(
        [
            html.Td('FirewallIP'),
            dbc.Input(
                id='FirewallIP-Input',
                placeholder=FirewallIP,
                value=str(FirewallIP),
                disabled=False,
                style={
                    'width': '100.1%',
                    'height': '43px',
                    'font-size': '20px'
                }
            )
        ]
    )
    RowList.append(Row)

    # FirewallPort
    Row = html.Tr(
        [
            html.Td('FirewallPort'),
            dbc.Input(
                id='FirewallPort-Input',
                placeholder=int(FirewallPort),
                value=int(FirewallPort),
                type='number',
                min=1,
                max=65535,
                style={
                    'width': '100.1%',
                    'height': '43px',
                    'font-size': '20px'
                }
            ),
        ]
    )
    RowList.append(Row),

    #GUI
    Row = html.Tr(
        [
            html.Td('GUI'),
            dcc.Dropdown(
                id='GUI-Dropdown',
                options=[
                    {'label': 'True', 'value': 'True'},
                    {'label': 'False', 'value': 'False'},
                ],
                value=str(Config.SetGui()),
                style={
                    'left': '-5px',
                    'top': '-4px',
                    'margin': '0px 0px',
                    'width': '101%',
                    'height': '43px',
                    'background-color': '#F5F5F5',
                    'font-size': '20px',
                }
            ),
        ]
    )
    RowList.append(Row)

    #LogSystem
    Statue,Path = Config.SetLogSystem()
    Row = html.Tr(
        [
            html.Td('LogSystem'),
            dcc.Dropdown(
                id='LogSystem-Dropdown',
                options=[
                    {'label': 'True', 'value': 'True'},
                    {'label': 'False', 'value': 'False'},
                ],
                value=str(Statue),
                style={
                    'left': '-5px',
                    'top': '-5px',
                    'margin': '0px 0px',
                    'width': '101%',
                    'height': '43px',
                    'background-color': '#F5F5F5',
                    'font-size': '20px',
                }
            ),
        ]
    )
    RowList.append(Row)

    #DatabasePath
    Row = html.Tr(
        [
            html.Td('DatabasePath'),
            dbc.Input(
                id='DatabasePath-Input',
                placeholder=Path,
                value=str(Path),
                style={
                    'width': '100.1%',
                    'height': '43px',
                    'font-size': '20px'
                }
            ),
        ]
    )
    RowList.append(Row),

    #MachineLearningCore
    Row = html.Tr(
        [
            html.Td('MachineLearningCore'),
            dcc.Dropdown(
                id='MachineLearningCore-Dropdown',
                options=[
                    {'label': 'TF-IDF_SVM_V1.0', 'value': 'TF-IDF_SVM_V1.0'},
                    {'label': 'TF-IDF_SVM_V1.1', 'value': 'TF-IDF_SVM_V1.1'},
                ],
                value=str(Config.SetClassifierCore()).split('/')[-1].split('.joblib')[0],
                style={
                    'left': '-5px',
                    'top': '-5px',
                    'margin': '0px 0px',
                    'width': '101%',
                    'height': '43px',
                    'background-color': '#F5F5F5',
                    'font-size':'20px',
                }
            ),
        ]
    )
    RowList.append(Row)

    TableBody = [html.Tbody(RowList)]
    Layout = html.Div(
        children=[
            dbc.Table(TableHeader + TableBody, bordered=False),
            html.Br(),
            dbc.ButtonGroup(
                [
                    dbc.Button(
                        id='Save',
                        children='Save',
                        style={
                            'font-size': '25px',
                            'margin': 'auto auto',
                            'display':'flex',
                            'justify-content':'center',
                            'align-items':'center'
                        }
                    ),
                    dcc.Upload(
                        id='Upload',
                        children=[
                            dbc.Button(
                                id='Upload-Button',
                                children='Upload',
                                style={
                                    'font-size': '25px',
                                    'margin': 'auto auto',
                                    'display': 'flex',
                                    'justify-content': 'center',
                                    'align-items': 'center'
                                }
                            )
                        ]
                    ),
                    dbc.Button(
                        id='Restart',
                        children='Restart',
                        style={
                            'font-size': '25px',
                            'margin': 'auto auto',
                            'display': 'flex',
                            'justify-content': 'center',
                            'align-items': 'center'
                        },
                        n_clicks=0,
                    ),
                ],
            size='lg',
            style={
                'font-size': '25px',
                'float': 'right',
                'margin': 'auto auto',
                },

            ),

            ],
        style={
            'font-size': '20px',
            'width': '95%',
            'margin': '5% auto',

        },

    )
    return Layout

def HtmlUpload():
    Layout = [
        html.Div(
            children=[
                dcc.Upload(
                    id='Upload-Data',
                    children=html.Div(
                        children=[
                            'Drag and Drop or ',
                            html.A(
                                children='Select File',
                                style={
                                    'color':'blue'
                                }
                            )
                        ]
                    ),
                    style={
                        'width': '100%',
                        'height': '60px',
                        'lineHeight': '60px',
                        'borderWidth': '1px',
                        'borderStyle': 'dashed',
                        'borderRadius': '5px',
                        'textAlign': 'center',
                        'margin': '10px'
                    },
                )
            ]
        )
    ]

    return Layout