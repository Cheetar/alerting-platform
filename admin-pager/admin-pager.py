import os
import sys
import time
import threading
import secrets
import logging
from decouple import config
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

root = logging.getLogger()
root.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)


def generate_token(token_length=32):
    return secrets.token_hex(token_length)


def has_admin_responded(token):
    # TODO retrieve from key-value store
    return False


def retrieve_service_details(service_name):
    # TODO retrieve from configuration manager
    return {'main_admin_email': "mateusz@sieniawski.net",
            'secondary_admin_email': "msieniawski98@gmail.com",
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
    time.sleep(allowed_response_time)
    if not has_admin_responded(token):
        notify_secondary_admin(secondary_admin_email, service_name)


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


handle_service_down("example.com")
