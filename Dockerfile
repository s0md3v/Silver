FROM python:3.8.7-alpine3.12
LABEL name=silver src=https://github.com/s0md3v/Silver.git creator=s0md3v maintainer=tbhaxor desc='Mass scan IPs for vulnerable services'

RUN apk update && apk upgrade && apk add build-base gcc nmap masscan linux-headers libc-dev
RUN mkdir /app
WORKDIR /app

COPY . .
RUN pip install -r requirements.txt
VOLUME [ "/app" ]

ENV PYTHONPATH=/app
ENTRYPOINT [ "python", "silver.py" ]
CMD [ "--help" ]