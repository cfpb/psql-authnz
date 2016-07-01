#!/usr/bin/env python

import pprint
import os, sys
import re
import logging

import ldap
import psycopg2

def connect_to_ldap(ldap_protocol, ldap_host, ldap_port, username, password):
    """
    Attempt to connect to Active Directory (LDAP)
    """
    try:
        ldap_connection_string = "{}://{}:{}".format(ldap_protocol, ldap_host, ldap_port)
        ldap_conn = ldap.initialize(ldap_connection_string)

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

    return ldap_conn

def get_data_access_groups(ldap_conn, group_ou, domain):
    """
    Retrieve all groups within the specified OU.
    """
    try:
        data_access_groups_search_base = group_ou + "," + domain
        data_access_groups = ldap_conn.search_s(data_access_groups_search_base, ldap.SCOPE_SUBTREE, "(objectCLass=groupOfNames)")
    except ldap.LDAPError, e:
        logging.error(e)
        sys.exit(1)

    groups = pprint.pformat(data_access_groups)
    logging.debug("Data access groups:".format())
    for line in groups.split('\n'):
        logging.debug(line)

    return data_access_groups

def extract_users(group_members):
    users = []
    for member in group_members:
        # Get the actual username
        user_match = re.search("uid=(?P<username>[a-zA-Z0-9\_\-\.\/\@]+),.*", member)

        if user_match:
            username = user_match.groups('username')[0]
            logging.debug("Extracted username '{}' from '{}'".format(username, member))
        else:
            logging.warning("Could not extract username from {}, skipping...".format(member))
            continue

        # Remove anthing after an @
        username = username.split("@")[0]

        users.append(username)

    logging.debug("User list from LDAP: {}".format(users))
    return users

def purge_unauthorized_users(psql_cur, role_name, authorized_users):
    """
    Removes users in 'role_name' that are not in 'authorized_users'
    """
    psql_cur.execute(
        """
        SELECT m.rolname as member
            FROM pg_authid p
            INNER JOIN pg_auth_members ON (p.oid=pg_auth_members.roleid)
            INNER JOIN pg_authid m ON (pg_auth_members.member = m.oid)
        WHERE p.rolname = '{}'
        """.format(role_name)
    )

    current_members = psql_cur.fetchall()
    logging.debug("Current group members: {}".format(current_members))

    for member in current_members:
        member = member[0]
        if member not in authorized_users:
            logging.info("Removing user '{}' from group '{}'".format(member, role_name))
            psql_cur.execute("REVOKE {} FROM {}".format(role_name, member))
            logging.debug(psql_cur.statusmessage)

def add_authorized_users(psql_cur, role_name, authorized_users):
    """
    Ensure 'authorized_users' are in 'role_name'
    """
    for user in authorized_users:
        # First, check if the user role exists
        psql_cur.execute("SELECT 1 FROM pg_roles WHERE rolname='{0}'".format(user))
        result = psql_cur.fetchone()
        if not result or result[0] == 0:
            logging.info("User role '{}' does not exist, creating...".format(user))
            psql_cur.execute("CREATE ROLE \"{}\" NOSUPERUSER NOCREATEDB NOCREATEROLE".format(user))

        # Then, add the user to the role
        psql_cur.execute("GRANT \"{}\" TO \"{}\"".format(role_name, user))

def syncronize_group(psql_cur, group):
    """
    Syncronize the membership between an LDAP group and a PostgreSQL role
    """
    group_name = group[1]['cn'][0]
    group_members = group[1]['member']
    logging.debug("Group '{0}' has members: {1}".format(group_name, group_members))

    role_match = None
    role_match = re.search('^{}(?P<role_name>[a-z0-9_]+)'.format(prefix), group_name)

    if role_match:
        role_name = role_match.groups('role_name')[0]
    else:
        logging.warning("Group '{0}' did not match the required pattern, skipping...".format(group_name))
        return

    # First, ensure that the role exists
    psql_cur.execute("SELECT 1 FROM pg_roles WHERE rolname='{0}'".format(role_name))
    result = psql_cur.fetchone()
    if not result or result[0] == 0:
        logging.warning("Group {0} does not have a corresponding role in Postgres, skipping...".format(group_name))
        return

    # Second, extract each member from the list.
    authorized_users = extract_users(group_members)

    # Third, remove all users that are not on the list
    purge_unauthorized_users(psql_cur, role_name, authorized_users)

    # Lastly, add authorized users to the role
    add_authorized_users(psql_cur, role_name, authorized_users)

    return

if __name__ == '__main__':
    # Retrieve settings from environment variables
    log_level       = os.getenv("PSQL_AUTHNZ_LOG_LEVEL", "warn")
    prefix          = os.getenv("PSQL_AUTHNZ_PREFIX", "")
    username        = os.getenv("PSQL_AUTHNZ_LDAP_USERNAME", None)
    password        = os.getenv("PSQL_AUTHNZ_LDAP_PASSWORD", None)
    ldap_protocol   = os.getenv("PSQL_AUTHNZ_LDAP_PROTOCOL", "ldap")
    ldap_host       = os.getenv("PSQL_AUTHNZ_LDAP_HOST", "10.0.1.127")
    ldap_port       = os.getenv("PSQL_AUTHNZ_LDAP_PORT", "389")
    domain          = os.getenv("PSQL_AUTHNZ_LDAP_DOMAIN", "dc=test,dc=dev")
    group_ou        = os.getenv("PSQL_AUTHNZ_GROUP_OU", "ou=Groups")
    user_ou         = os.getenv("PSQL_AUTHNZ_USER_OU", "ou=Users")
    pg_host         = os.getenv("PGHOST", "")
    pg_user         = os.getenv("PGUSER", "")
    pg_password     = os.getenv("PGPASSWORD", "")

    # Setup logging
    LOG_FORMAT = "%(asctime)-15s PSQL-AUTHNZ [%(levelname)-5s]: %(message)s"
    logging.basicConfig(format=LOG_FORMAT,level=getattr(logging, log_level.upper()))

    ldap_conn = connect_to_ldap(ldap_protocol, ldap_host, ldap_port, username, password)

    data_access_groups = get_data_access_groups(ldap_conn, group_ou, domain)

    # Connect to Postgres using provided credentials
    try:
        psql_conn = psycopg2.connect("dbname=postgres user={} host={} password={}".format(pg_user, pg_host, pg_password))
        psql_conn.autocommit = True
        psql_cur = psql_conn.cursor()
    except psycopg2.Error as e:
        logging.error(e)
        sys.exit(1)

    # Iterate over each group to retrieve its members.
    for group in data_access_groups:
        syncronize_group(psql_cur, group)

    psql_cur.close()
    psql_conn.close()

    sys.exit(0)
