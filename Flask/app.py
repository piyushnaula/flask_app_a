from flask import Flask
from flask import request
app=Flask(__name__)
@app.route("/hello_world1")
def hello_world1():
    return "<h1>Hello, World1!</h1>"
@app.route("/hello_world2")
def hello_world2():
    return "<h1>Hello, World2!</h1>"
@app.route("/hello_world3")
def hello_world3():
    return "<h1>Hello, World3!</h1>"
@app.route("/test1")
def test1():
    a=5+6
    return "This is my function to run app{}".format(a)
@app.route("/test2")
def test2():
    data=request.args.get('x')
    return "This is a data input form my url {}".format(data)
if __name__=="__main__":
    app.run(host="0.0.0.0")