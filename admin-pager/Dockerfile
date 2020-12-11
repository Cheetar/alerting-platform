FROM python

WORKDIR /app
ADD requirements.txt /app
RUN pip install -r requirements.txt

ADD . /app
EXPOSE 80

CMD ["python", "admin-pager.py"]
