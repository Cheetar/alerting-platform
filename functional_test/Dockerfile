FROM python

WORKDIR /app
ADD requirements.txt /app
RUN pip install -r requirements.txt

ADD . /app
ENV GOOGLE_APPLICATION_CREDENTIALS="/app/google-application-credentials.json"

CMD ["python", "/app/functional-test.py"]