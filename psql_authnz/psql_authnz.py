#!/usr/bin/env python
import os, sys
import logging
import logstash
import time

from .synchronizer import Synchronizer
from .exceptions import PSQLAuthnzException

def main():
    # Retrieve settings from environment variables
    psql_period     = os.getenv("PSQL_AUTHNZ_PERIOD", 300)
    log_level       = os.getenv("PSQL_AUTHNZ_LOG_LEVEL", "info")
    log_file        = os.getenv("PSQL_AUTHNZ_LOG_FILE", None)
    group_prefix    = os.getenv("PSQL_AUTHNZ_PREFIX", "")
    username        = os.getenv("PSQL_AUTHNZ_LDAP_USERNAME", None)
    password        = os.getenv("PSQL_AUTHNZ_LDAP_PASSWORD", None)
    ldap_protocol   = os.getenv("PSQL_AUTHNZ_LDAP_PROTOCOL", "ldap")
    ldap_host       = os.getenv("PSQL_AUTHNZ_LDAP_HOST", "10.0.1.127")
    ldap_port       = os.getenv("PSQL_AUTHNZ_LDAP_PORT", "389")
    domain          = os.getenv("PSQL_AUTHNZ_LDAP_DOMAIN", "dc=test,dc=dev")
    method          = os.getenv("PSQL_AUTHNZ_LDAP_METHOD", "SIMPLE")
    fieldname       = os.getenv("PSQL_AUTHNZ_LDAP_FIELD", "userPrincipalName")  #The LDAP field to use as username
    group_ou        = os.getenv("PSQL_AUTHNZ_GROUP_OU", "ou=Groups")
    group_class     = os.getenv("PSQL_AUTHNZ_GROUP_CLASS", "groupOfNames")
    global_groups   = os.getenv("PSQL_AUTHNZ_GLOBAL_GROUPS", None)
    blacklist       = os.getenv("PSQL_AUTHNZ_BLACKLIST", "").split(",")
    logstash_host   = os.getenv("PSQL_AUTHNZ_LOGSTASH_HOST", None)
    logstash_port   = os.getenv("PSQL_AUTHNZ_LOGSTASH_PORT", None)
    pg_ident_file   = os.getenv("PSQL_AUTHNZ_PG_IDENT_FILE", None)
    pg_host         = os.getenv("PGHOST", None)
    pg_user         = os.getenv("PGUSER", None)
    pg_password     = os.getenv("PGPASSWORD", None)
    default_db        = os.getenv("PSQL_AUTHNZ_DEFAULT_DB_NAME", None)
    is_citus        = os.getenv("PSQL_AUTHNZ_IS_CITUS", 0)
    exit_code       = 0

    # These are groups that all users should be a part of.
    if global_groups:
        global_groups = global_groups.split(",")

    # Setup logging
    logger = logging.getLogger(__name__)
    logger.setLevel(getattr(logging, log_level.upper()))

    LOG_FORMAT = ("%(asctime)-15s PSQL-AUTHNZ " +
                 "[%(levelname)-5s]:" +
                 "%(filename)-15s:%(lineno)-3s - %(message)s")

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        logger.addHandler(file_handler)
    else:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        logger.addHandler(console_handler)

    if logstash_host and logstash_port:
        logstash_handler = logstash.TCPLogstashHandler(
            logstash_host,
            int(logstash_port),
            tags=["psql-authnz",],
            version=1
        )
        logger.addHandler(logstash_handler)

    while exit_code == 0:
        with Synchronizer(global_groups=global_groups,
                          logger=logger,
                          pg_ident_file=pg_ident_file,
                          username_field=fieldname,
                          is_citus=is_citus,
                          default_db=default_db) as synchronizer:

            try:
                synchronizer.connect_to_ldap(
                    ldap_protocol, ldap_host, ldap_port,
                    username, password, method
                )
                synchronizer.connect_to_psql(
                    pg_user, pg_host, pg_password
                )
                synchronizer.synchronize(
                    group_ou, group_class, domain,
                    group_prefix, blacklist
                )

            except PSQLAuthnzException as e:
                logging.error("Fatal synchronization error: {0}".format(e))
                time.sleep(5)
                exit_code = 1
            except Exception as e:
                logging.error("Unexpected error encountered: {0}".format(e))
                time.sleep(5)
                exit_code = 1

        try:
            time.sleep(int(psql_period))
        except (ValueError, TypeError) as e:
            logging.error("PSQL_AUTHNZ_PERIOD is not an integer, exiting!")

    return exit_code
