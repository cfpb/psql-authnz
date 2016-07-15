#!/usr/bin/env python
import os, sys
import logging

from .synchronizer import Synchronizer
from .exceptions import PSQLAuthnzException

def main():
    # Retrieve settings from environment variables
    log_level       = os.getenv("PSQL_AUTHNZ_LOG_LEVEL", "info")
    group_prefix    = os.getenv("PSQL_AUTHNZ_PREFIX", "")
    username        = os.getenv("PSQL_AUTHNZ_LDAP_USERNAME", None)
    password        = os.getenv("PSQL_AUTHNZ_LDAP_PASSWORD", None)
    ldap_protocol   = os.getenv("PSQL_AUTHNZ_LDAP_PROTOCOL", "ldap")
    ldap_host       = os.getenv("PSQL_AUTHNZ_LDAP_HOST", "10.0.1.127")
    ldap_port       = os.getenv("PSQL_AUTHNZ_LDAP_PORT", "389")
    domain          = os.getenv("PSQL_AUTHNZ_LDAP_DOMAIN", "dc=test,dc=dev")
    method          = os.getenv("PSQL_AUTHNZ_LDAP_METHOD", "SIMPLE")
    group_ou        = os.getenv("PSQL_AUTHNZ_GROUP_OU", "ou=Groups")
    pg_host         = os.getenv("PGHOST", None)
    pg_user         = os.getenv("PGUSER", None)
    pg_password     = os.getenv("PGPASSWORD", None)
    exit_code       = 0

    # Setup logging
    LOG_FORMAT = "%(asctime)-15s PSQL-AUTHNZ [%(levelname)-5s]: %(filename)-15s:%(lineno)-3s - %(message)s"
    logging.basicConfig(format=LOG_FORMAT,level=getattr(logging, log_level.upper()))

    with Synchronizer() as synchronizer:
        try:
            synchronizer.connect_to_ldap(ldap_protocol, ldap_host, ldap_port, username, password, method)
            synchronizer.connect_to_psql(pg_user, pg_host, pg_password)

            logging.info("Synchronizing server {} to {},{}.".format(pg_host, group_ou, domain))
            synchronizer.synchronize(group_ou, domain, group_prefix)
        except PSQLAuthnzException:
            exit_code = 1

    return exit_code
