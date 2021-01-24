import threading
import requests
from google.cloud import pubsub_v1
import logging
from decouple import config

subscription_path = "projects/magnetic-port-293211/subscriptions/request_topic-sub"

publisher = pubsub_v1.PublisherClient()
publisher_path = "projects/magnetic-port-293211/topics/unavailability_report"


services_timeout = 5
threads_number = 10


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
    print(threading.get_ident())
    if not 'service_url' in message.attributes:
        message.ack()
        print("Request has not url")
        return
    if not test_service_available(message.attributes['service_url']):
        submit_unavailability(message.attributes['service_url'])
    message.ack()


if __name__ == "__main__":
    subscriber_shutdown = threading.Event()
    futures = list()
    subscribers = list()
    for i in range(0, threads_number):
        my_subscriber = pubsub_v1.SubscriberClient()
        future = my_subscriber.subscribe(subscription_path,
                                         callback=callback)
        future.add_done_callback(lambda res: subscriber_shutdown.set())
        futures.append(future)
        subscribers.append(my_subscriber)
    try:
        subscriber_shutdown.wait()
    except KeyboardInterrupt:
        print("KeyboardInterrupt")
    finally:
        for f in futures:
            f.cancel()
        for s in subscribers:
            s.close()
