from ubuntu:bionic

RUN apt-get update && apt-get install locales=2.27-3ubuntu1 git python3.6 python3-pip -qy && \
pip3 install --upgrade pip setuptools && \
if [ ! -e /usr/bin/pip ]; then ln -s pip3 /usr/bin/pip ; fi && \
if [ ! -e /usr/bin/python ]; then ln -sf /usr/bin/python3 /usr/bin/python; fi && \
rm -rf /var/lib/apt/lists/*

# Set the locale
RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

WORKDIR /app
ADD requirements/requirements.txt /app/requirements/requirements.txt
ADD requirements/development.txt /app/requirements/development.txt
ADD requirements/pip-tools.txt /app/requirements/pip-tools.txt
RUN pip install pip-tools
RUN pip install -r /app/requirements/development.txt


ADD . /app
RUN pip install -e .
