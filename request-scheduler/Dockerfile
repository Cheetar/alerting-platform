FROM python

WORKDIR /app
ADD requirements.txt /app
RUN pip install -r requirements.txt

ADD . /app
ENV GOOGLE_APPLICATION_CREDENTIALS="/app/google-application-credentials.json"
EXPOSE 8080

CMD ["gunicorn", "-w 1", "--threads=4", "-b 0.0.0.0:8080", "request-scheduler:app"]
