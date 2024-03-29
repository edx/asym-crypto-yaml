from ubuntu:focal

RUN apt-get update && apt-get install locales git python3.8 python3.8-distutils python3.8-dev python3-pip -qy && \
if [ ! -e /usr/bin/pip ]; then ln -s pip3 /usr/bin/pip ; fi && \
if [ ! -e /usr/bin/python ]; then ln -sf /usr/bin/python3 /usr/bin/python; fi && \
pip install --upgrade pip setuptools && \
rm -rf /var/lib/apt/lists/*

# Set the locale
RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

WORKDIR /app
ADD requirements/base.txt /app/requirements/base.txt
ADD requirements/development.txt /app/requirements/development.txt
ADD requirements/pip-tools.txt /app/requirements/pip-tools.txt
RUN pip install pip-tools
RUN pip install -r /app/requirements/development.txt


ADD . /app
RUN pip install -e .
