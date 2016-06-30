#!/usr/bin/env python

import pprint
import os, sys

import logging

import ldap


if __name__ == '__main__':
    log_level   = os.getenv("PSQL_AUTHNZ_LOG_LEVEL", "warn")
    username    = os.getenv("PSQL_AUTHNZ_LDAP_USERNAME", None)
    password    = os.getenv("PSQL_AUTHNZ_LDAP_PASSWORD", None)
    domain      = os.getenv("PSQL_AUTHNZ_LDAP_DOMAIN", "dc=test,dc=dev")
    group_ou    = os.getenv("PSQL_AUTHNZ_GROUP_OU", "ou=Groups")
    user_ou     = os.getenv("PSQL_AUTHNZ_USER_OU", "ou=Users")

    LOG_FORMAT = "%(asctime)-15s PSQL-AUTHNZ: %(message)s"
    logging.basicConfig(format=LOG_FORMAT,level=getattr(logging, log_level.upper()))

    try:
        conn = ldap.initialize('ldap://10.0.1.127:389')

        # If a username and password is provided, we assume
        # SASL's DIGESTMD5 authentication method.
        if username and password:
            auth_tokens = ldap.sasl.digest_md5(username, password)
            conn.sasl_interactive_bind_s("", auth_tokens)
        else:
            conn.simple_bind_s()
    except ldap.LDAPError, e:
        logging.error(e)
        sys.exit(1)

    try:
        data_access_groups_search_base = group_ou + "," + domain
        data_access_groups = conn.search_s(data_access_groups_search_base, ldap.SCOPE_SUBTREE, "(objectCLass=groupOfNames)")
    except ldap.LDAPError, e:
        logging.error(e)
        sys.exit(1)

    logging.debug("Data access groups: \n{0}".format(pprint.pformat(data_access_groups)))

    for group in data_access_groups:
        logging.debug("Group '{0}' has members: {1}".format(group[1]['cn'][0], group[1]['member']))

    # TODO: Remove this section, just for testing purposes
    try:
        user_search_base = user_ou + "," + domain
        users = conn.search_s(user_search_base, ldap.SCOPE_SUBTREE, "(objectClass=*)")
    except ldap.LDAPError, e:
        logging.error(e)
        sys.exit(1)

    logging.debug("Users: \n{0}".format(pprint.pformat(users)))
    sys.exit(0)
