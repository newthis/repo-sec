from flask import Flask
from flask import request
from RepoSecScan import RepoSecScan
import json

yj = RepoSecScan()
yj.init_rules()

app = Flask(__name__)

@app.route('/scan_one', methods=['POST'])
def scan_one():
    # get url
    data = json.loads(request.data.decode())
    content = data["content"]
    customRegex = data["c_regex"]
    rss = yj.scan_one(content, customRegex)
    result = {}
    result["result"] = rss
    return json.dumps(result)

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0' ,port=8182)