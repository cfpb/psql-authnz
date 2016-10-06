import sys
import pprint
import logging
import re

import psycopg2
import ldap

from .exceptions import PSQLAuthnzLDAPException, PSQLAuthnzPSQLException

class Synchronizer:
    def __init__(self, global_groups=None):
        """
        Initializes a syncronizer, with placeholders for the LDAP and PSQL
        connections, plus an optional `global_groups` variable for groups
        that all users should be added to.
        """
        self.ldap_conn = None
        self.psql_conn = None
        self.psql_cur = None
        self.global_groups = global_groups

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.psql_conn:
            if self.psql_cur:
                self.psql_cur.close()
            self.psql_conn.close()

    def connect_to_ldap(self, ldap_protocol, ldap_host, ldap_port, username, password, method='BASIC'):
        """
        Attempt to connect to Active Directory (LDAP)
        """
        try:
            ldap_connection_string = "{}://{}:{}".format(ldap_protocol, ldap_host, ldap_port)
            self.ldap_conn = ldap.initialize(ldap_connection_string)
            self.ldap_conn.set_option(ldap.OPT_REFERRALS, 0)

            # If a username and password is provided, we assume
            # SASL's DIGESTMD5 authentication method.
            logging.debug("Connecting using method: {0}".format(method))
            if method == "DIGESTMD5":
                if username and password:
                    logging.debug("Username and password provided, attempting DIGEST MD5 connection.")
                    auth_tokens = ldap.sasl.digest_md5(username, password)
                    self.ldap_conn.sasl_interactive_bind_s("", auth_tokens)
                else:
                    raise PSQLAuthnzLDAPException("A username and password must supplied for DIGESTMD5 authentication.")
            else:
                if username and password:
                    logging.debug("Username and password provided, attempting simple bind connection.")
                    self.ldap_conn.simple_bind_s(username, password)
                else:
                    logging.debug("No username and password provided, attempting anonymous connection.")
                    self.ldap_conn.simple_bind_s()
        except Exception as e:
            logging.error(unicode(e.message).encode('utf-8'))
            raise PSQLAuthnzLDAPException()

    def connect_to_psql(self, pg_user, pg_host, pg_password):
        # Connect to Postgres using provided credentials
        conn_string = "dbname=postgres"

        if pg_user:
            conn_string += " user={}".format(pg_user)
        if pg_host:
            conn_string += " host={}".format(pg_host)
        if pg_password:
            conn_string += " password={}".format(pg_password)

        try:
            self.psql_conn = psycopg2.connect(conn_string)
            self.psql_conn.autocommit = True
            self.psql_cur = self.psql_conn.cursor()
        except psycopg2.Error as e:
            logging.error(e)
            raise PSQLAuthnzPSQLException()

    def get_groups(self, group_ou, group_class, domain):
        """
        Retrieve all groups within the specified OU.
        """
        try:
            groups_search_base = group_ou + ',' + domain
            logging.debug("Group search base: {0}".format(groups_search_base))
            groups = self.ldap_conn.search_s(groups_search_base, ldap.SCOPE_SUBTREE, "(objectClass={0})".format(group_class))
        except ldap.LDAPError, e:
            logging.error(e)
            raise PSQLAuthnzLDAPException("Failed to get groups from the specified OU.")

        groups_formatted = pprint.pformat(groups)
        logging.debug("Data access groups:")
        for line in groups_formatted.split('\n'):
            logging.debug(line)

        logging.info("Retrieved {} group(s) to synchronize.".format(len(groups)))

        return groups

    def extract_users(self, group_members):
        users = []
        for member in group_members:
            # Get the actual username
            user_match = re.search("uid=(?P<username>[a-zA-Z0-9\_\-\.\/\@]+),.*", member)

            if user_match:
                username = user_match.groups('username')[0]
                logging.debug("Extracted username '{}' from '{}'".format(username, member))
            else:
                try:
                    # UID not contained in DN, attempt to retrieve it via LDAP.
                    member_attrs = self.ldap_conn.search_s(member, ldap.SCOPE_BASE, "(objectClass=*)")
                except ldap.LDAPError, e:
                    logging.error(e)
                    raise PSQLAuthnzLDAPException("Failed to retrieve user attributes from supplied DN.")

                logging.debug(member_attrs)

                if member_attrs:
                    username = member_attrs[0][1]["userPrincipalName"][0]
                else:
                    logging.warning("Could not extract or lookup username from {}, skipping...".format(member))
                    continue

            # Remove anything after an @
            username = username.split("@")[0]

            users.append(username.lower())

        logging.debug("User list from LDAP: {}".format(users))
        return users

    def purge_unauthorized_users(self, role_name, authorized_users):
        """
        Removes users in 'role_name' that are not in 'authorized_users'
        """
        self.psql_cur.execute(
            """
            SELECT m.rolname as member
                FROM pg_authid p
                INNER JOIN pg_auth_members ON (p.oid=pg_auth_members.roleid)
                INNER JOIN pg_authid m ON (pg_auth_members.member = m.oid)
            WHERE p.rolname = '{}'
            """.format(role_name)
        )

        current_members = self.psql_cur.fetchall()
        logging.debug("Current group members: {}".format(current_members))

        for member in current_members:
            member = member[0]
            if member not in authorized_users:
                logging.info("Removing user '{}' from group '{}'".format(member, role_name))
                self.psql_cur.execute("REVOKE {} FROM {}".format(role_name, member))
                logging.debug(self.psql_cur.statusmessage)

    def add_authorized_users(self, role_name, authorized_users):
        """
        Ensure 'authorized_users' are in 'role_name'
        """
        for user in authorized_users:
            # First, check if the user role exists, and create it if it does not
            self.psql_cur.execute(
                "SELECT 1 FROM pg_roles WHERE rolname='{0}' AND rolcanlogin='t'".format(user)
            )
            result = self.psql_cur.fetchone()
            if not result or result[0] == 0:
                logging.info("Created new role '{}'".format(user))
                self.psql_cur.execute(
                    """
                    CREATE ROLE \"{}\" LOGIN INHERIT NOSUPERUSER NOCREATEDB \
                        NOCREATEROLE
                    """.format(user)
                )

                if self.global_groups:
                    logging.info(
                        "Adding user {0} to global groups: {1}".format(
                            user, ", ".join(self.global_groups)
                        )
                    )

                    for group in self.global_groups:
                        self.psql_cur.execute(
                            """
                            GRANT {0} TO {1}
                            """.format(group, user)
                        )
            #else:
                # Role exists, ensure that it is a login role
            #    self.psql_cur.execute(
            #        "SELECT rolcanlogin FROM pg_roles WHERE rolname='{}'".format(user)
            #    )

            #    can_login = self.psql_cur.fetchone()

            #    if can_login and can_login[0] == 'f':
            #        self.psql_cur.execute(
            #            "UPDATE pg_roles SET rolcanlogin='t' WHERE rolname='{}'".format(user)
            #        )

            # Then, add the user to the role
            self.psql_cur.execute("GRANT \"{}\" TO \"{}\"".format(role_name, user))

    def synchronize_group(self, group, prefix, blacklist):
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
            return False

        if role_name in blacklist:
            return False

        # First, ensure that the role exists
        self.psql_cur.execute("SELECT 1 FROM pg_roles WHERE rolname='{0}'".format(role_name))
        result = self.psql_cur.fetchone()
        if not result or result[0] == 0:
            logging.warning("Group {0} does not have a corresponding role in Postgres, skipping...".format(group_name))
            return False

        # Second, extract each member from the list.
        authorized_users = self.extract_users(group_members)

        # Third, add authorized users to the role
        self.add_authorized_users(role_name, authorized_users)

        # Lastly, remove all users that are not on the list
        self.purge_unauthorized_users(role_name, authorized_users)

        return True

    def synchronize(self, group_ou, group_class, domain, prefix, blacklist):
        group_count = 0
        for group in self.get_groups(group_ou, group_class, domain):
            if self.synchronize_group(group, prefix, blacklist):
                group_count += 1

        logging.info("Successfully synchronized {} group(s) from {},{}".format(group_count, group_ou, domain))
