import requests
from google.cloud import pubsub_v1
from decouple import config

subscriber = pubsub_v1.SubscriberClient()
subscription_path = subscriber.subscription_path(
    config('GOOGLE_CLOUD_PROJECT_ID'),
    config('PUBSUB_TOPIC')
)

publisher = pubsub_v1.PublisherClient()
topic_path = publisher.topic_path(
    config('GOOGLE_CLOUD_PROJECT_ID'),
    config('PUBSUB_TOPIC_REPORT')
)


services_timeout = config('SERVICES_TIMEOUT')


def submit_unavailability():
    return None


def test_service_available(url):
    available = False
    try:
        request = requests.get(url, timeout=services_timeout)
        if request.status_code == 200:
            available = True
            print("Service {} is available.".format(url))
        else:
            available = False
            print("Service {} is not available.".format(url))
    except TimeoutError:
        available = False
        print("Service {} timeout.".format(url))
    return available


def callback(message):
    print(f"Received {message}.")
    if not test_service_available(message.url_service):
        submit_unavailability(message.url_service)
    message.ack()


if __name__ == "__main__":
    streaming_pull_future = subscriber.subscribe(subscription_path,
                                                 callback=callback)
    with subscriber:
        try:
            streaming_pull_future.result(timeout=5.0)
        except TimeoutError:
            streaming_pull_future.canel()
