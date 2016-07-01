#!/usr/bin/env python

import pprint
import os, sys
import re
import logging

import ldap
import psycopg2

if __name__ == '__main__':
    log_level   = os.getenv("PSQL_AUTHNZ_LOG_LEVEL", "warn")
    username    = os.getenv("PSQL_AUTHNZ_LDAP_USERNAME", None)
    password    = os.getenv("PSQL_AUTHNZ_LDAP_PASSWORD", None)
    domain      = os.getenv("PSQL_AUTHNZ_LDAP_DOMAIN", "dc=test,dc=dev")
    group_ou    = os.getenv("PSQL_AUTHNZ_GROUP_OU", "ou=Groups")
    user_ou     = os.getenv("PSQL_AUTHNZ_USER_OU", "ou=Users")
    hostname    = os.getenv("PSQL_AUTHNZ_HOSTNAME", "localhost")

    LOG_FORMAT = "%(asctime)-15s PSQL-AUTHNZ: %(message)s"
    logging.basicConfig(format=LOG_FORMAT,level=getattr(logging, log_level.upper()))

    # Attempt to connect to Active Directory (LDAP)
    try:
        ldap_conn = ldap.initialize('ldap://10.0.1.127:389')

        # If a username and password is provided, we assume
        # SASL's DIGESTMD5 authentication method.
        if username and password:
            auth_tokens = ldap.sasl.digest_md5(username, password)
            ldap_conn.sasl_interactive_bind_s("", auth_tokens)
        else:
            ldap_conn.simple_bind_s()
    except ldap.LDAPError, e:
        logging.error(e)
        sys.exit(1)

    # Retrieve all groups within the specified OU.
    try:
        data_access_groups_search_base = group_ou + "," + domain
        data_access_groups = ldap_conn.search_s(data_access_groups_search_base, ldap.SCOPE_SUBTREE, "(objectCLass=groupOfNames)")
    except ldap.LDAPError, e:
        logging.error(e)
        sys.exit(1)

    logging.debug("Data access groups: \n{0}".format(pprint.pformat(data_access_groups)))

    try:
        psql_conn = psycopg2.connect("dbname=postgres user=postgres host={1}".format(db_name, hostname))
        psql_cur = psql_conn.cursor()
    except psycopg2.Error as e:
        logging.error(e)
        sys.exit(1)

    # Iterate over each group to retrieve its members.
    for group in data_access_groups:
        group_name = group[1]['cn'][0]
        group_members = group[1]['member']
        logging.debug("Group '{0}' has members: {1}".format(group_name, group_members))

        try:
            role_match = re.search('^_grp_(?P<role_name>[a-z0-9_]+)')
        except:
            logging.warning("Group {0} did not match the required pattern!".format(group_name))

        role_name = role_match.groups('role_name')

        # First, ensure that the role exists
        psql_cur.execute("SELECT 1 FROM pg_roles WHERE rolname='{0}'".format(role_name))

        if cur.fetchone() != (0,):
            logging.warning("Group {0} does not have a corresponding role in Postgres, skipping...".format(group_name))
            continue

    psql_cur.close()
    psql_conn.close()

    # TODO: Remove this section, just for testing purposes
    try:
        user_search_base = user_ou + "," + domain
        users = ldap_conn.search_s(user_search_base, ldap.SCOPE_SUBTREE, "(objectClass=*)")
    except ldap.LDAPError, e:
        logging.error(e)
        sys.exit(1)

    logging.debug("Users: \n{0}".format(pprint.pformat(users)))

    sys.exit(0)
