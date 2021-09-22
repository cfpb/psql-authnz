FROM centos/python-36-centos7

ENV PYTHONUNBUFFERED 1

USER root

RUN yum update -y && yum install -y epel-release && \ 
    yum install -y cyrus-sasl-plain python36-devel openldap-devel openssl-devel && \
    yum install -y postgresql postgresql-devel

