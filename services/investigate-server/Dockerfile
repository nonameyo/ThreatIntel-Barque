# base image
FROM python:3.13.0rc1-slim

# set working directory
RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

# add requirements
COPY ./requirements.txt /usr/src/app/requirements.txt


# install requirements
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# add app
COPY . /usr/src/app

# RUN groupadd -g 999 appuser && \
#     useradd -r -u 999 -g appuser appuser
# USER appuser
