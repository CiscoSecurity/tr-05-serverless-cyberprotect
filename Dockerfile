FROM alpine:3.14
LABEL maintainer="Ian Redden <iaredden@cisco.com>"

# install packages we need
RUN apk update && apk add --no-cache musl-dev openssl-dev gcc py3-configobj \
supervisor git libffi-dev uwsgi-python3 uwsgi-http jq syslog-ng uwsgi-syslog \
py3-pip python3-dev

# do the Python dependencies
ADD code /app
RUN pip3 install -r /app/requirements.txt
RUN chown -R uwsgi.uwsgi /etc/uwsgi

# copy over scripts to init
ADD scripts /
RUN mv /uwsgi.ini /etc/uwsgi
RUN chmod +x /*.sh

# entrypoint
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/start.sh"]
