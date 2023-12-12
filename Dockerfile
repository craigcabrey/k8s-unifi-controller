FROM python:3

WORKDIR /usr/src/app
COPY . .

RUN pip install -r requirements.txt --no-cache

ENTRYPOINT ["python3", "unifi-operator.py"]
