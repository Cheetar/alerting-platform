FROM python

WORKDIR /app
ADD requirements.txt /app
RUN pip install -r requirements.txt

ADD . /app
ENV GOOGLE_APPLICATION_CREDENTIALS="/app/google-application-credentials.json"
EXPOSE 8080

CMD ["gunicorn", "-w 5", "--threads=1", "-b 0.0.0.0:8080", "request-sender:flask_app"]
