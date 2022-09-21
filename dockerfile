FROM python:3.9.12

RUN mkdir /home/app
WORKDIR /home/app

RUN pip install -r requirements.txt

CMD ["uwsgi","config.ini"]