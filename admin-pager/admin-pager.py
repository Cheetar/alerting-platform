import os
import sys
import time
import threading
import secrets
import logging
from decouple import config
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from google.cloud import datastore
from datetime import datetime
from flask import Flask

app = Flask(__name__)
datastore_client = datastore.Client()

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
    # TODO retrieve from configuration manager
    return {'main_admin_email': "msieniawski98@gmail.com",
            'secondary_admin_email': "mateusz@sieniawski.net",
            'allowed_response_time': 300,
            }


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


def notify_main_admin(admin_email, service_name):
    subject = f"{service_name} is down"
    token = generate_token()
    html_content = f"Dear administrator of {service_name},<br/><br/>Service {service_name} is down. Please respond to this message by visiting {config('URL')}/notifies/{token}. Otherwise, the second administrator will also be notified.<br/><br/>Sincerely,<br/>Alerting platform team"
    send_mail(admin_email, subject, html_content)
    return token


def notify_secondary_admin(admin_email, service_name):
    subject = f"{service_name} is down"
    html_content = f"Dear administrator of {service_name},<br/><br/>Service {service_name} is down.<br/><br/>Sincerely,<br/>Alerting platform team"
    send_mail(admin_email, subject, html_content)


def handle_notifying_admins(service_name, main_admin_email, secondary_admin_email, allowed_response_time):
    token = notify_main_admin(main_admin_email, service_name)
    store_log(f"Admin {main_admin_email} has been notified about {service_name} being down.")
    time.sleep(allowed_response_time)
    if not has_admin_responded(token):
        notify_secondary_admin(secondary_admin_email, service_name)
        store_log(f"Secondary admin {secondary_admin_email} has been notified about {service_name} being down.")


def handle_service_down(service_name):
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


@app.route('/service-down/<service_name>/')
def service_down(service_name):
    handle_service_down(service_name)
    return "OK"


@app.route('/health/')
def health():
    return "OK"


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
