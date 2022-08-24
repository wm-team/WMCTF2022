from flask import Flask,request
import requests
import traceback


# 帮大家缩小搜索范围了捏，只需要url target token参数，使用其他参数的是非预期（非预期太简单了捏）
# Only url target token parameters is needed, other methods using other parameters exist and are unintended (unintended ways are too easy)
ALLOWED_ARGS = ["url","target","token"]

app = Flask(__name__)

# 给出提示 Gives hints
@app.route("/")
def root():
    return 'try /version or /sub?target=clash&url=http://front/example'

# 转发请求到后端 Forward request to backend
@app.route("/<path:path>" , methods=["GET"])
def proxy(path):
    # 防止非预期 Prevent unexpected behavior
    if '?' in path or '%3f' in str(path).lower(): # 禁止参数走私 No parameter smuggling
        return "'?' in path is not allowed.", 400
    for key in request.args.keys():
        if key not in ALLOWED_ARGS: # 限制参数 Only allowed parameters
            return "Parameter '{}' is not allowed. Allowed parameters: {}".format(key,str(ALLOWED_ARGS)), 400
        if type(request.args[key]) != type('114514'): # 禁止数组 No array
            return "Array is not allowed.", 400
    # 转发请求 Forward Request
    params = {}
    for key in request.args.keys():
        params[key] = request.args[key]
    try:
        r = requests.get("http://app:25500/" + path, params=params,timeout=5)
        return r.text,r.status_code
    except Exception as e:
        # this should not happen unless the server is down
        return "Timeout\n" +traceback.format_exc(e), 500

# 示例数据 Example data
@app.route("/example")
def example():
    return '''proxies:
  - {name: EXAMPLE_DATA, server: 114.514.1919.810, port: 11451, type: trojan, password: dQw4w9WgXcQ}'''

if __name__ == "__main__":
    app.run(host="0.0.0.0",port=80,debug=False)