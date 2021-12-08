from flask import Flask,request,send_file
app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'hello world'

@app.route('/GetTest',methods=['GET'])
def GetTest():
    id = request.args.get("id")
    test = request.args.get("test")
    print(id)
    return "id = " + str(id)

@app.route('/PostTest',methods=['POST'])
def PostTest():
    recv = request.form
    Param = {}
    for index,content in recv.items():
        Param[index] = content
    print(Param["id"])
    return "id = " + str(Param["id"])

if __name__ == '__main__':
    app.run(host="192.168.238.129",port=5000)