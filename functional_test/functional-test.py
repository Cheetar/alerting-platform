import os
import sys
import time
import secrets
import threading
import logging
import requests

from decouple import config
from datetime import datetime

from google.cloud import datastore
from kubernetes.client.rest import ApiException
from kubernetes import client
from kubernetes import config as k8s_config
from google.cloud.container_v1 import ClusterManagerClient
from google.oauth2 import service_account


datastore_client = datastore.Client()

SCOPES = ['https://www.googleapis.com/auth/cloud-platform']
credentials = service_account.Credentials.from_service_account_file(os.getenv('GOOGLE_APPLICATION_CREDENTIALS'),
                                                                    scopes=SCOPES)
cluster_manager_client = ClusterManagerClient(credentials=credentials)
cluster = cluster_manager_client.get_cluster(project_id=config("PROJECT_ID"),
                                             zone=config("ZONE"),
                                             cluster_id=config("CLUSTER_ID"))
cluster_configuration = client.Configuration()
cluster_configuration.host = "https://" + cluster.endpoint + ":443"
cluster_configuration.verify_ssl = False
cluster_configuration.api_key = {"authorization": "Bearer " + credentials.token}
client.Configuration.set_default(cluster_configuration)

kubernetes_client = client.CoreV1Api()

requests.packages.urllib3.disable_warnings()

root = logging.getLogger()
root.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)


def generate_token(token_length=32):
    return secrets.token_hex(token_length)


email_token = generate_token()
MAIN_ADMIN_EMAIL = f"{email_token}@bar.com"
SECONDARY_ADMIN_EMAIL = f"{email_token}2@bar.com"
ALERTING_WINDOW = 2  # seconds
ALLOWED_RESPONSE_TIME = 2  # seconds
FREQUENCY = 1  # RPS

CONFIGURATION_MANAGER_URL = "http://" + config('CONFIGURATION_MANAGER_SERVICE_NAME') + f".default.svc.cluster.local"
CONFIGURATION = None


def get_fake_service_ip():
    result = kubernetes_client.list_namespaced_service(namespace="default", watch=False)
    for item in result.items:
        if item.metadata.name == config("FAKE_SERVICE_SERVICE_NAME"):
            return item.status.load_balancer.ingress[0].ip
    return None


def add_fake_service_to_monitoring(fake_service_ip):
    global CONFIGURATION
    CONFIGURATION = {
        'service_url': f"{fake_service_ip}/test-service/",
        'frequency': FREQUENCY,
        'alerting_window': ALERTING_WINDOW,
        'main_admin_email': MAIN_ADMIN_EMAIL,
        'secondary_admin_email': SECONDARY_ADMIN_EMAIL,
        'allowed_response_time': ALLOWED_RESPONSE_TIME,
        }
    headers = {'Content-Type': 'application/json', 'Accept':'application/json'}
    requests.put(f"{CONFIGURATION_MANAGER_URL}/configurations/", json=[CONFIGURATION], headers=headers)


def remove_fake_service_from_monitoring(fake_service_ip):
    requests.delete(f"{CONFIGURATION_MANAGER_URL}/configurations/", json=[CONFIGURATION])


def turn_on_fake_service():
    requests.get("http://" + config('FAKE_SERVICE_SERVICE_NAME') + f".default.svc.cluster.local/set-available/")


def turn_off_fake_service():
    requests.get("http://" + config('FAKE_SERVICE_SERVICE_NAME') + f".default.svc.cluster.local/set-unavailable/")


def get_admin_pager_pod_name():
    ret = kubernetes_client.list_pod_for_all_namespaces(watch=False)
    admin_pager_pod_name = None
    for item in ret.items:
        if "admin-pager" in item.metadata.name:
            return item.metadata.name
    logging.info("Not found running admin pager pod")
    return None


def check_logs_contains(admin_email):
    query = datastore_client.query(kind='Log')
    fake_service_ip = get_fake_service_ip()
    msg = f"Admin {admin_email} has been notified about {fake_service_ip}/test-service/ being down."
    query.add_filter("message", "=", msg)
    res = query.fetch(limit=1)
    if len(list(res)) > 0:
        return True
    return False


if __name__ == "__main__":
    logging.info(f"Turning on the fake service...")
    turn_on_fake_service()
    fake_service_ip = get_fake_service_ip()
    logging.info(f"Retrived the fake service external IP: {fake_service_ip}")
    logging.info(f"Adding fake service to monitoring...")
    add_fake_service_to_monitoring(fake_service_ip)

    logging.info(f"Waiting for {2 * ALERTING_WINDOW} seconds...")
    time.sleep(2 * ALERTING_WINDOW)

    # The fake service is running, check that admin is not informed
    logging.info(f"Checking if admin was not notified...")
    if not check_logs_contains(MAIN_ADMIN_EMAIL):
        logging.info("[OK] Admin not informed")
    else:
        logging.info("[ERROR] Admin informed, but service runs")

    logging.info(f"Turning off the fake service...")
    turn_off_fake_service()

    logging.info(f"Waiting for {2 * ALERTING_WINDOW} seconds...")
    time.sleep(2 * ALERTING_WINDOW)

    # The fake service is running, check that admin is not informed
    logging.info(f"Checking if the main admin was notified...")
    if check_logs_contains(MAIN_ADMIN_EMAIL):
        logging.info("[OK] The main admin was informed")
    else:
        logging.info("[ERROR] The main admin not informed, but the fake service is down")

    logging.info(f"Waiting for {2 * ALLOWED_RESPONSE_TIME} seconds...")
    time.sleep(2 * ALLOWED_RESPONSE_TIME)

    # The fake service is running, check that admin is not informed
    logging.info(f"Checking if the secondary admin was notified...")
    if check_logs_contains(SECONDARY_ADMIN_EMAIL):
        logging.info("[OK] The secondary admin was informed")
    else:
        logging.info("[ERROR] The secondary admin not informed, but the fake service is down")

    logging.info(f"Removing the fake service from monitoring...")
    remove_fake_service_from_monitoring(fake_service_ip)

    logging.info(f"Functional test finished.")
