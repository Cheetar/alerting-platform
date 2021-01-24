import os
import sys
import logging
import threading
from decouple import config
from google.cloud import datastore
from flask import Flask, request, Response, jsonify
from flask_expects_json import expects_json
from kubernetes import client
from google.cloud.container_v1 import ClusterManagerClient
from google.oauth2 import service_account
import requests

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


def assign_services_to_pods(pods, configurations):
    assignment = {}
    for pod in pods:
        assignment[pod] = []
    for i in range(len(configurations)):
        assignment[pods[i % len(pods)]].append(dict(configurations[i]))
    return assignment


def get_pods_list():
    result = kubernetes_client.list_namespaced_pod(namespace="default", label_selector="app=request-scheduler",
                                                   watch=False)
    pods = []
    for item in result.items:
        if item.status.phase == "Running" and item.status.container_statuses[0].state.running:
            pods.append(str(item.status.pod_ip) + ":" + str(item.spec.containers[0].ports[0].container_port))
    return pods


def get_all_configurations():
    query = datastore_client.query(kind="Configuration")
    query.order = ["frequency"]
    results = list(query.fetch())
    return results


def send_configurations_to_pods(assignment):
    for pod in assignment:
        requests.post("http://" + pod + "/configurations", json=assignment.get(pod))


def reschedule():
    configurations = get_all_configurations()
    pods = get_pods_list()
    if len(pods) > 0:
        assignment = assign_services_to_pods(pods, configurations)
        send_configurations_to_pods(assignment)


def get_datastore_key(service_url):
    kind = "Configuration"
    key = datastore_client.key(kind, service_url)
    return key


def save_configs_to_db(configurations):
    entities_to_save = []
    with datastore_client.transaction():
        for single_service_config in configurations:
            key = get_datastore_key(single_service_config.get("service_url"))
            configuration_entity = datastore.Entity(key=key)
            configuration_entity.update({
                'service_url': single_service_config.get("service_url"),
                'frequency': single_service_config.get("frequency"),
                'alerting_window': single_service_config.get("alerting_window"),
                'main_admin_email': single_service_config.get("main_admin_email"),
                'secondary_admin_email': single_service_config.get("secondary_admin_email"),
                'allowed_response_time': single_service_config.get("allowed_response_time"),
            })
            entities_to_save.append(configuration_entity)
        datastore_client.put_multi(entities_to_save)


def delete_configs_from_db(configurations):
    keys_to_delete = []
    with datastore_client.transaction():
        for single_service_config in configurations:
            keys_to_delete.append(get_datastore_key(single_service_config.get("service_url")))
        datastore_client.delete_multi(keys_to_delete)


configurations_schema = {
    'type': 'array',
    'items': {
        'type': 'object',
        'properties': {
            'service_url': {'type': 'string'},
            'frequency': {'type': 'integer'},
            'alerting_window': {'type': 'integer'},
            'main_admin_email': {'type': 'string'},
            'secondary_admin_email': {'type': 'string'},
            'allowed_response_time': {'type': 'integer'},
        },
        'required': ['service_url', 'frequency', 'alerting_window', 'main_admin_email', 'secondary_admin_email',
                     'allowed_response_time']
    }
}

service_url_schema = {
    'type': 'object',
    'properties': {
        'service_url': {'type': 'string'},
    },
    'required': ['service_url']
}


@app.before_first_request
def before_first_request():
    th = threading.Thread(target=reschedule)
    th.start()


@app.route('/configurations/', methods=['PUT'])
@expects_json(configurations_schema)
def update_configurations():
    configurations = request.get_json()
    try:
        save_configs_to_db(configurations)
    except Exception as e:
        logging.error(e)
        return Response(
            "Configurations update failed",
            status=500,
        )
    th = threading.Thread(target=reschedule)
    th.start()
    return "OK"


@app.route('/configurations/', methods=['DELETE'])
@expects_json(configurations_schema)
def delete_configurations():
    configurations = request.get_json()
    try:
        delete_configs_from_db(configurations)
    except Exception as e:
        logging.error(e)
        return Response(
            "Configurations update failed",
            status=500,
        )
    th = threading.Thread(target=reschedule)
    th.start()
    return "OK"


@app.route('/configurations/', methods=['GET'])
def get_configurations():
    try:
        configurations = get_all_configurations()
    except Exception as e:
        logging.error(e)
        return Response(
            "Configurations get failed",
            status=500,
        )
    return jsonify(configurations)


@app.route('/service-details/', methods=['POST'])
@expects_json(service_url_schema)
def get_service_details():
    data = request.get_json()
    service_url = data["service_url"]
    key = get_datastore_key(service_url)
    configuration = datastore_client.get(key)
    if configuration is None:
        return Response(
            service_url + " details not found",
            status=400,
        )
    if "error" in configuration:
        return Response(
            configuration.get("error").get("message"),
            status=configuration.get("error").get("code"),
        )
    return jsonify(
        main_admin_email=configuration.get("main_admin_email"),
        secondary_admin_email=configuration.get("secondary_admin_email"),
        allowed_response_time=configuration.get("allowed_response_time")
    )


@app.route('/new-pod/')
def handle_new_pod():
    th = threading.Thread(target=reschedule)
    th.start()
    return "OK"


@app.route('/health/')
def health():
    return "OK"


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
