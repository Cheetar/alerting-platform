import requests
from google.cloud import pubsub_v1
import logging
from decouple import config

subscriber = pubsub_v1.SubscriberClient()
subscription_path = "projects/magnetic-port-293211/subscriptions/request_topic-sub"

publisher = pubsub_v1.PublisherClient()
publisher_path = "projects/magnetic-port-293211/topics/unavailability_report"


services_timeout = 5 # config('SERVICES_TIMEOUT')


def submit_unavailability(url):
    publisher.publish(publisher_path, b'Report', service_url=url)
    print("Service {} reported.".format(url))


def test_service_available(url):
    try:
        request = requests.get(url, timeout=services_timeout)
        if request.status_code == 200:
            result = True
            print("Service {} is available.".format(url))
        else:
            result = False
            print("Service {} is not available.".format(url))
    except TimeoutError:
        result = False
        print("Service {} timeout.".format(url))
    except Exception as e:
        result = False
        print("Service {} unavailable.".format(url))
    return result


def callback(message):
    if not 'service_url' in message.attributes:
        message.ack()
        return
    if not test_service_available(message.attributes['service_url']):
        submit_unavailability(message.attributes['service_url'])
    message.ack()


if __name__ == "__main__":
    streaming_pull_future = subscriber.subscribe(subscription_path,
                                                 callback=callback)
    with subscriber:
        try:
            streaming_pull_future.result()
        except TimeoutError:
            streaming_pull_future.canel()
