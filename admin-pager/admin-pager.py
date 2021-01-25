import os
import sys
import time
import threading
import secrets
import logging
import requests

from decouple import config
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from google.cloud import datastore
from datetime import datetime
from flask import Flask, request
from flask_expects_json import expects_json

from kubernetes import client
from google.cloud.container_v1 import ClusterManagerClient
from google.oauth2 import service_account

app = Flask(__name__)
datastore_client = datastore.Client()


SCOPES = ['https://www.googleapis.com/auth/cloud-platform']
credentials = service_account.Credentials.from_service_account_file(os.getenv('GOOGLE_APPLICATION_CREDENTIALS'),
                                                                    scopes=SCOPES)
cluster_manager_client = ClusterManagerClient(credentials=credentials)
cluster = cluster_manager_client.get_cluster(project_id=config("PROJECT_ID"), zone=config("ZONE"),
                                             cluster_id=config("CLUSTER_ID"))
cluster_configuration = client.Configuration()
cluster_configuration.host = "https://" + cluster.endpoint + ":443"
cluster_configuration.verify_ssl = False
cluster_configuration.api_key = {"authorization": "Bearer " + credentials.token}
client.Configuration.set_default(cluster_configuration)

kubernetes_client = client.CoreV1Api()

root = logging.getLogger()
root.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)


def generate_token(token_length=32):
    return secrets.token_hex(token_length)


def get_current_datetime():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def store_log(message):
    kind = "Log"
    token = generate_token()
    log_key = datastore_client.key(kind, token)
    log = datastore.Entity(key=log_key)

    log["datetime"] = get_current_datetime()
    log["message"] = message
    datastore_client.put(log)

    logging.info(message)


def has_admin_responded(token):
    query = datastore_client.query(kind='Admin response')
    query.add_filter("token", "=", token)
    res = query.fetch(limit=1)
    if len(list(res)) > 0:
        return True
    return False


def save_admin_response(token):
    kind = "Admin response"
    admin_response_key = datastore_client.key(kind, token)
    admin_response = datastore.Entity(key=admin_response_key)

    admin_response["token"] = token
    admin_response["datetime"] = get_current_datetime()
    datastore_client.put(admin_response)

    message = f"Admin responded to service being down. Event token: {admin_response.key.name}"
    store_log(message)
    logging.info(message)


def retrieve_service_details(service_name):
    """ Example response
            return {'main_admin_email': "msieniawski98@gmail.com",
            'secondary_admin_email': "mateusz@sieniawski.net",
            'allowed_response_time': 300}
    """
    headers = {'Content-Type': 'application/json', 'Accept':'application/json'}
    response = requests.post("http://" + config('CONFIGURATION_MANAGER_SERVICE_NAME') + f".default.svc.cluster.local/service-details/",
                             json={"service_url": service_name}, headers=headers)
    return response.json()


def send_mail(to_emails, subject, html_content):
    message = Mail(
        from_email=config('SENDGRID_SENDER_EMAIL'),
        to_emails=to_emails,
        subject=subject,
        html_content=html_content
    )
    try:
        logging.info("Sending an e-mail...")
        sg = SendGridAPIClient(config('SENDGRID_API_KEY'))
        response = sg.send(message)
        logging.info(response.status_code)
        logging.info(response.body)
        logging.info(response.headers)
    except Exception as e:
        logging.error("Sending failed!")
        logging.error(e)


def get_admin_pager_service_ip():
    result = kubernetes_client.list_namespaced_service(namespace="default", watch=False)
    for item in result.items:
        if item.metadata.name == config("ADMIN_PAGER_SERVICE_NAME"):
            return item.status.load_balancer.ingress[0].ip
    return None


def notify_main_admin(admin_email, service_name):
    subject = f"{service_name} is down"
    token = generate_token()
    admin_pager_external_ip = get_admin_pager_service_ip()
    html_content = f"Dear administrator of {service_name},<br/><br/>Service {service_name} is down. Please respond to this message by visiting http://{admin_pager_external_ip}/notifies/{token}. Otherwise, the second administrator will also be notified.<br/><br/>Sincerely,<br/>Alerting platform team"
    send_mail(admin_email, subject, html_content)
    return token


def notify_secondary_admin(admin_email, service_name):
    subject = f"{service_name} is down"
    html_content = f"Dear administrator of {service_name},<br/><br/>Service {service_name} is down.<br/><br/>Sincerely,<br/>Alerting platform team"
    send_mail(admin_email, subject, html_content)


def handle_notifying_admins(service_name, main_admin_email, secondary_admin_email, allowed_response_time):
    logging.info(f"Handling notifying admins {main_admin_email} and {secondary_admin_email} that service {service_name} is down...")
    token = notify_main_admin(main_admin_email, service_name)
    store_log(f"Admin {main_admin_email} has been notified about {service_name} being down.")
    logging.info(f"Waiting for the main admin response...")
    time.sleep(allowed_response_time)
    if not has_admin_responded(token):
        logging.info(f"Main admin has not responded...")
        logging.info(f"Notyfing second admin...")
        notify_secondary_admin(secondary_admin_email, service_name)
        logging.info(f"Second admin has been notified")
        store_log(f"Admin {secondary_admin_email} has been notified about {service_name} being down.")


def handle_service_down(service_name):
    logging.info(f"Retrieving service {service_name} details...")
    service_details = retrieve_service_details(service_name)
    main_admin_email = service_details.get('main_admin_email')
    secondary_admin_email = service_details.get('secondary_admin_email')
    allowed_response_time = service_details.get('allowed_response_time')
    try:
        th = threading.Thread(target=handle_notifying_admins,
                              args=(service_name, main_admin_email, secondary_admin_email, allowed_response_time,))
        th.start()
    except Exception as e:
        logging.error(e)


@app.route('/notifies/<token>/')
def admin_responded(token):
    save_admin_response(token)
    return "Thank you for responding to the event."


schema = {
    'type': 'object',
    'properties': {
        'service_url': {'type': 'string'},
    },
    'required': ['service_url']
}


@app.route('/service-down/', methods=['POST'])
@expects_json(schema)
def service_down():
    """ Example data: {"service_url": "www.google.com/"}
    """
    logging.info("Service down called")
    data = request.get_json()
    service_url = data["service_url"]
    logging.info(f"Handling {service_url} being down...")
    handle_service_down(service_url)
    return "OK"


@app.route('/health/')
def health():
    return "OK"


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=9080)
