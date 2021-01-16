import sys
import time
import threading
import logging
import requests
from decouple import config
from flask import Flask, request
from flask_expects_json import expects_json
from google.cloud import pubsub_v1

app = Flask(__name__)

publisher = pubsub_v1.PublisherClient()
topic_name = 'projects/{project_id}/topics/{topic}'.format(
    project_id=config('GOOGLE_CLOUD_PROJECT_ID'),
    topic=config('PUBSUB_TOPIC'),
)

root = logging.getLogger()
root.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

config_version = 0
lock = threading.Lock()


def ping_configuration_manager():
    requests.get("http://" + config('CONFIGURATION_MANAGER_SERVICE_NAME') + ".default.svc.cluster.local/new-pod")


def send_to_queue(service_url, alerting_window):
    publisher.publish(topic_name, b'Request', service_url=service_url, alerting_window=str(alerting_window))
    logging.info(service_url + " " + str(alerting_window))


def schedule_single_service_requests(actual_config_version, configuration):
    initial_config_version = actual_config_version()
    while True:
        time.sleep(configuration['frequency'])
        if initial_config_version == actual_config_version():
            send_to_queue(configuration['service_url'], configuration['alerting_window'])


def schedule_requests(configurations):
    for single_service_config in configurations:
        try:
            th = threading.Thread(target=schedule_single_service_requests,
                                  args=(lambda: config_version, single_service_config,))
            th.start()
        except Exception as e:
            logging.error(e)


schema = {
    'type': 'array',
    'items': {
        'type': 'object',
        'properties': {
            'service_url': {'type': 'string'},
            'frequency': {'type': 'integer'},
            'alerting_window': {'type': 'integer'}
        },
        'required': ['service_url', 'frequency', 'alerting_window']
    }
}


@app.before_first_request
def before_first_request():
    ping_configuration_manager()


@app.route('/configurations/', methods=['POST'])
@expects_json(schema)
def update_configurations():
    global config_version
    with lock:
        config_version += 1
    req_data = request.get_json()
    schedule_requests(req_data)
    return "OK"


@app.route('/health/')
def health():
    return "OK"


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
