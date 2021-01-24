import sys
import threading
import logging
from flask import Flask

app = Flask(__name__)

root = logging.getLogger()
root.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

isResponding = True
lock = threading.Lock()


@app.route('/set-unavailable/', methods=['GET'])
def set_service_unavailable():
    global isResponding
    with lock:
        isResponding = False
    return "OK"


@app.route('/set-available/', methods=['GET'])
def set_service_available():
    global isResponding
    with lock:
        isResponding = True
    return "OK"


@app.route('/test-service/', methods=['GET'])
def test_service():
    if isResponding:
        return "OK"
    else:
        return "Service not responding", 500


@app.route('/health/')
def health():
    return "OK"


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
