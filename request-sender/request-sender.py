import sys
import threading
import logging
import time
import requests
from google.api_core import retry
from google.cloud import pubsub_v1
from decouple import config
from flask import Flask


root = logging.getLogger()
root.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)


subscription_path = 'projects/{project_id}/subscriptions/{topic}'.format(
    project_id=config('PROJECT_ID'),
    topic=config('PUBSUB_REQUESTS_TOPIC'),
)


services_timeout = int(config('SERVICES_TIMEOUT'))
threads_number = int(config('THREADS_NUMBER'))


def submit_unavailability(url):
    headers = {'Content-Type': 'application/json', 'Accept':'application/json'}
    try:
        logging.info("Report " + url)
        requests.post("http://" + config('ADMIN_PAGER_SERVICE_NAME') + f".default.svc.cluster.local/service-down/",
                      json={"service_url": url}, headers=headers)
    except:
        logging.info("Do not send email.")


def test_service_available(url, alert_window):
    try:
        request = requests.get("http://" + url, timeout=services_timeout)
        if request.status_code == 200:
            logging.info("Available " + url)
            return True
        else:
            logging.info("Wait " + url)
            raise Exception()
    except (TimeoutError, Exception):
        time.sleep(alert_window)
        try:
            request2 = requests.get("http://" + url, timeout=services_timeout)
            if request2.status_code == 200:
                logging.info("Available " + url)
                return True
            else:
                raise Exception()
        except (TimeoutError, Exception):
            logging.info("Unavailable " + url)
            return False


def callback(message):
    if 'service_url' not in message.attributes or 'alerting_window' not in message.attributes:
        logging.info("Attributes not complete")
        message.ack()
        return
    if not test_service_available(message.attributes['service_url'],
                                  int(message.attributes['alerting_window'])):
        submit_unavailability(message.attributes['service_url'])
    message.ack()


def request_sender():
    while True:
        subscriber = pubsub_v1.SubscriberClient()
        future = subscriber.subscribe(subscription_path, callback)
        with subscriber:
            try:
                future.result()
            except (TimeoutError, Exception):
                future.cancel()


threading.Thread(target=request_sender).start()
flask_app = Flask(__name__)


@flask_app.route('/health/')
def health():
    return "OK"