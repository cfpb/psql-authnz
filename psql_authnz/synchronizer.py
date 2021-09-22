import pprint
import logging
import re

import psycopg2
import ldap

from .exceptions import PSQLAuthnzLDAPException, PSQLAuthnzPSQLException

from typing import Union
from logging import Logger


class Synchronizer:
    """Initalizes the synchroinzer to connect and synchronize both LDAP and PSQL

    Args:
        logger (Logger): Application logger object
        global_groups (list, optional):  All users will be added to these groups
        pg_ident_file (str, optional): PG Ident mapping file location
        field_name (str 'userPrincipalName'):  LDAP field to use to split off from OU
        is_citus (bool, false): Determines if application will run in citus mode
        default_db: (str, optional): Default database name

    Attributes:
        ldap_connection (ldap.LDAPObject): LDAP connection object
        psql_connection (psycopg2.Connection): PSQL Database connection
        psql_cursor (psycopg2.Connection.cursor): Database cursor
        global_groups (None, list): Optional, all users will be added to these groups
        logger (logging.Logger): Application logger (stream/file/logstash)
        pg_ident_file (None, str): Pg Ident mapping file location
        is_citus (bool): Determines if application will run in citus mode
        fieldname (str): LDAP Field to use to split off from OU
        default_db (str): Default database name
    """

    def __init__(
        self,
        logger: Logger,
        global_groups: Union[list, None] = None,
        pg_ident_file: str = None,
        field_name: str = "userPrinicpalName",
        is_citus: bool = False,
        default_db: str = None,
    ):

        self.ldap_connection = None
        self.psql_connection = None
        self.psql_cursor = None
        self.global_groups = global_groups
        self.logger = logger or logging.getLogger(__name__)
        self.pg_ident_file = pg_ident_file
        self.is_citus = is_citus
        self.field_name = field_name
        self.default_db = default_db

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.psql_connection:
            if self.psql_cursor:
                self.psql_cursor.close()
            self.psql_connection.close()

    def connect_to_ldap(
        self,
        ldap_protocol: str,
        ldap_host: str,
        ldap_port: str,
        username: str,
        password: str,
        method: str = "BASIC",
    ) -> None:
        """Attempt to connect to Active Directory (LDAP)

        Args:
            ldap_protocol (str): protocol to use
            ldap_host (str): LDAP host to connect too
            ldap_port (str): LDAP port to use
            username (str): username to use
            password (str): password to use
            method (str, optional): LDAP connection method

        Raises:
            PSQLAuthnzLDAPException: Generic exception to raise
        """
        self.logger.debug("Attempting to connect to LDAP...")

        try:
            conn_string = f"{ldap_protocol}://{ldap_host}:{ldap_port}"

            self.logger.debug(f"Connection string: {conn_string}")

            self.ldap_connection = ldap.initialize(conn_string)
            self.ldap_connection.set_option(ldap.OPT_REFERRALS, 0)

            # If a username and password is provided, we assume
            # SASL's DIGESTMD5 authentication method.
            self.logger.debug(f"Auth using method: {method}")
            if method == "DIGESTMD5":
                if username and password:
                    self.logger.debug(
                        (
                            "Username and password provided,"
                            + " attempting DIGEST MD5 connection."
                        )
                    )
                    auth_tokens = ldap.sasl.digest_md5(username, password)
                    self.ldap_connection.sasl_interactive_bind_s("", auth_tokens)
                else:
                    raise PSQLAuthnzLDAPException(
                        (
                            "A username and password must supplied "
                            + "for DIGESTMD5 authentication."
                        )
                    )
            else:
                if username and password:
                    self.logger.debug, (
                        (
                            """
                            Username and password provided,
                            attempting simple bind connection.
                        """
                        )
                    )
                    self.ldap_connection.simple_bind_s(username, password)
                else:
                    self.logger.debug(
                        (
                            "No username and password provided, "
                            + "attempting anonymous connection."
                        )
                    )
                    self.ldap_connection.simple_bind_s()

        except Exception as e:
            self.logger.error(e)
            raise PSQLAuthnzLDAPException()

    def connect_to_psql(self, pg_user: str, pg_host: str, pg_password: str) -> None:
        """Connects the application to the PSQL

        Args:
            pg_user (str): Postgres username
            pg_host (str): Postgres host
            pg_password (str): Postgres Password

        Raises:
            pyscopg2.Error: Generic connection error
            PSQLAuthnzPSQLException: Specfic error
        """
        conn_string = "dbname=postgres"

        self.logger.debug("Attempting to connect to PSQL...")

        if pg_user:
            conn_string += " user={}".format(pg_user)
        if pg_host:
            conn_string += " host={}".format(pg_host)
        if pg_password:
            conn_string += " password={}".format(pg_password)

        self.logger.debug(f"Connection string: {conn_string}")
        try:
            self.psql_connection = psycopg2.connect(conn_string)
            self.psql_connection.autocommit = True
            self.psql_cursor = self.psql_connection.cursor()
        except psycopg2.Error as e:
            self.logger.error(e)
            raise PSQLAuthnzPSQLException()
        except Exception as e:
            self.logger.error(e)
            raise e

    def get_groups(self, group_ou: str, group_class: str, domain: str) -> list:
        """Retrieve all groups within the specified OU

        Note:
            Example:
                `dn: cn=Users,ou=Groups,dc=example,dc=org
                changetype: add
                cn: Users
                objectclass: groupOfNames
                member: cn=user_gh,dc=example,dc=org
                member: cn=user_server,dc=example,dc=org
                member: cn=super,dc=example,dc=org`

            To target this one, it would be:
                group_ou: Groups
                domain: dc=example,dc=org
                group_class: groupOfNames

        Args:
            group_ou (str): Group OU to target
            group_class (str): Group class to target for retrieval
            domain (str): Domain to target

        Returns:
            groups (list): all groups found

        Raises:
            PSQLAuthnzLDAPException: If a LDAPFailure were to occur
            Exception: All other exceptions
        """
        self.logger.debug("Retriving LDAP groups...")
        try:
            groups_search_base = group_ou + "," + domain
            self.logger.debug(f"Group search base: {groups_search_base}")
            groups = self.ldap_connection.search_s(
                groups_search_base, ldap.SCOPE_SUBTREE, f"(objectClass={group_class})"
            )

        except ldap.LDAPError as e:
            self.logger.error(e)
            raise PSQLAuthnzLDAPException("Failed to get groups from the specified OU.")
        except Exception as e:
            self.logger.error(e)
            raise e

        self.logger.info(f"Retrieved {len(groups)} group(s) to synchronize...")

        for group in groups:
            self.logger.debug(f"Found group: {group[0]}")

        return groups

    def extract_users(self, group_members: list) -> list:
        """Extracts all users from a given group_member list

        Args:
            group_members (list): List of members

        Returns:
            users (list) all users parsed out

        Raises:
            PSQLAuthnzLDAPException: Failure attempting ot extract user attributes
            IndexError: If the member attributes parsing fiales
            KeyError: If the memeber attribute doesn't contain the `file_name`
            ValueError: If `field_name` contains a bad value
        """

        users = []
        for member in group_members:
            # Get the actual username
            member = member.decode("utf-8")
            user_match = re.search(
                "uid=(?P<username>[a-zA-Z0-9\_\-\.\/\@]+),.*", member
            )
            if user_match:
                username = user_match.groups("username")[0]
                self.logger.debug(f"Extracted username '{username}' from '{member}'")
            else:
                try:
                    # UID not contained in DN, attempt to retrieve it via LDAP.
                    member_attrs = self.ldap_connection.search_s(
                        member, ldap.SCOPE_BASE, "(objectClass=*)"
                    )
                except ldap.LDAPError as e:
                    self.logger.error(e)
                    raise PSQLAuthnzLDAPException(
                        "Failed to retrieve user attributes from supplied DN."
                    )
                except Exception as e:
                    self.logger.error(e)
                    raise e

                if member_attrs:
                    # First check if this is actually a nested group
                    member_type = ','.join([x.decode('utf-8') for x in member_attrs[0][1].get('objectClass', ['unknown'])])
                    member_dn = member_attrs[0][1].get('member', [])
                    self.logger.debug(
                        f"Member {member_dn} is of type: { member_type }"
                    )

                    if 'groupOfNames' in member_type or 'group' in member_type:
                        users.extend(self.extract_users(member_dn))
                        continue

                    # Not a nested group, so extract username
                    try:
                        username = member_attrs[0][1][self.field_name][0]
                    except (IndexError, KeyError, ValueError) as e:
                        self.logger.error(
                            f"Failed to get fieldname from attrs: {member_attrs}"
                        )
                        raise e
                else:
                    self.logger.warning(
                        "Couldn't extract fieldname for {member}, skipping..."
                    )
                    continue

            users.append(str(username, "utf-8"))

        return users

    def add_pgident_mapping(self, user: str) -> None:
        """Adds the pg ident mapping file

        Args:
            user (str): Username to check if it's in the mapping
        """

        if not self.pg_ident_file:
            self.logger.info("No pg_ident file has been defined.")
            return

        try:
            with open(self.pg_ident_file, "r") as f:
                pg_ident_entries = f.readlines()

            line_found = False

            for line in pg_ident_entries:
                if user in line:
                    self.logger.debug(f"pg_ident entry found for user {user}: {line}")
                    line_found = True

            if not line_found:
                self.logger.debug(f"No pg_ident entry found, creating entry for {user}")
                with open(self.pg_ident_file, "a") as f:
                    f.write("krb\t{user}\t{user.lower()}\n")

        except IOError as e:
            self.logger.error(f"Error updating pg_ident file: {str(e)}")

    def remove_pgident_mapping(self, user: str) -> None:
        """Placeholder for function to remove a user from the pgident mapping file.

        Args:
            user (str): Username to check if it's in the pgident file
        """
        pass

    def purge_unauthorized_users(self, role_name: str, authorized_users: list) -> None:
        """Removes users in `role_name` that are not in `authorized_users`

        Args:
            role_name (str): Rolename used to remove users
            authorized_users (list): List of authorized users

        Raises:
            PSQLAuthnzPSQLException: Database exception
            Exception: General unaccounted for exceptions
        """
        lowercase_users = [
            x.lower().replace("'", "").replace('"', "") for x in authorized_users
        ]

        self.logger.debug(f"Authorized users for role {role_name}: {authorized_users}")

        try:
            self.psql_cursor.execute(
                f"""
                SELECT m.rolname as member
                    FROM pg_authid p
                    INNER JOIN pg_auth_members ON (p.oid=pg_auth_members.roleid)
                    INNER JOIN pg_authid m ON (pg_auth_members.member = m.oid)
                    WHERE p.rolname = '{role_name}'
                """
            )
        except psycopg2.Error as e:
            self.logger.error(e)
            raise PSQLAuthnzPSQLException()
        except Exception as e:
            self.logger.error(e)
            raise e

        current_members = self.psql_cursor.fetchall()
        self.logger.debug(f"Actual users in role {role_name}: {current_members}")

        for member in current_members:
            member = member[0]
            if member not in lowercase_users:
                self.logger.info(f"Removing user '{member}' from group '{role_name}'")
                try:
                    self.psql_cursor.execute(f"REVOKE {role_name} FROM {member}")
                    if self.is_citus:
                        self.psql_cursor.execute(
                            f"""
                        SELECT RUN_COMMAND_ON_WORKERS($CMD$ REVOKE {role_name} FROM {member} $CMD$)
                        """
                        )

                except psycopg2.Error as e:
                    self.logger.error(e)
                    raise PSQLAuthnzPSQLException()
                except Exception as e:
                    self.logger.error(e)
                    raise e

                self.logger.debug(self.psql_cursor.statusmessage)

            # TODO: Look up each user in LDAP and make sure they
            # still exist and are active

    def add_authorized_users(self, role_name: str, authorized_users: list) -> None:
        """Ensure 'authorized_users' are in 'role_name'

         Args:
            role_name (str): Rolename used to remove users
            authorized_users (list): List of authorized users

        Raises:
            PSQLAuthnzPSQLException: Database exception
            Exception: General unaccounted for exceptions
        """

        for user in authorized_users:
            lowercase_user = user.lower().replace("'", "").replace('"', "")

            # First, check if the user role exists, and create it if it does not
            try:
                self.psql_cursor.execute(
                    f"""
                    SELECT 1 FROM pg_roles
                        WHERE rolname='{lowercase_user}' AND rolcanlogin='t'
                    """
                )
                result = self.psql_cursor.fetchone()
            except psycopg2.Error as e:
                self.logger.error(e)
                raise PSQLAuthnzPSQLException()
            except Exception as e:
                self.logger.error(e)
                raise e

            if not result or result[0] == 0:
                self.logger.info(f"Creating new role '{lowercase_user}'")
                try:
                    query = f"""
                        CREATE ROLE \"{lowercase_user}\" LOGIN INHERIT NOSUPERUSER \
                            NOCREATEDB NOCREATEROLE
                        """
                    self.logger.debug(f"Running query {query}")
                    self.psql_cursor.execute(query)
                except psycopg2.Error as e:
                    self.logger.error(e)
                    raise PSQLAuthnzPSQLException()

                if self.default_db is not None:
                    self.logger.debug(
                        f"Allowing {lowercase_user} to connect to db {self.default_db}."
                    )
                    try:
                        query = f"""
                           GRANT CONNECT ON DATABASE \"{self.default_db}\" TO \"{lowercase_user}\"
                           """
                        self.logger.debug(f"Running query {query}")
                        self.psql_cursor.execute(query)
                    except psycopg2.Error as e:
                        self.logger.error(e)
                        raise PSQLAuthnzPSQLException()

                if self.is_citus:
                    self.logger.debug(
                        f"Creating user role {lowercase_user} on Citus workers."
                    )
                    query = f"""
                       SELECT run_command_on_workers($cmd$ CREATE ROLE {lowercase_user} LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE $cmd$)
                       """
                    self.logger.debug(f"Running query {query}")
                    self.psql_cursor.execute(query)

                    if self.default_db is not None:
                        self.logger.debug(
                            f"Allowing {lowercase_user} to connect to db {self.default_db} on Citus Workers."
                        )
                        query = f"""
                           SELECT run_command_on_workers($cmd$ GRANT CONNECT ON DATABASE {self.default_db} TO {lowercase_user} $cmd$)
                           """
                        self.logger.debug(f"Running query {query}")
                        self.psql_cursor.execute(query)

                self.add_pgident_mapping(user)

                if self.global_groups:
                    self.logger.info(
                        f"Adding new user {lowercase_user} to global groups: {', '.join(self.global_groups)}"
                    )

                    for group in self.global_groups:
                        try:
                            self.psql_cursor.execute(
                                f"GRANT {group} TO {lowercase_user}"
                            )
                            if self.is_citus:
                                self.psql_cursor.execute(
                                    f"""
                                SELECT RUN_COMMAND_ON_WORKERS($CMD$ GRANT {group} TO {lowercase_user} $CMD$)
                                """
                                )
                        except psycopg2.Error as e:
                            self.logger.error(e)
                            raise PSQLAuthnzPSQLException()
                        except Exception as e:
                            self.logger.error(e)
                            raise e

            # Then, add the user to the role if not already present.
            try:
                self.psql_cursor.execute(
                    f"""
                    SELECT 1 FROM pg_authid g
                        INNER JOIN pg_auth_members ON
                            (g.oid=pg_auth_members.roleid)
                        INNER JOIN pg_authid u ON
                            (pg_auth_members.member=u.oid)
                        WHERE g.rolname = '{role_name}' AND u.rolname = '{lowercase_user}'
                    """
                )
                result = self.psql_cursor.fetchone()
            except psycopg2.Error as e:
                self.logger.error(e)
                raise PSQLAuthnzPSQLException()
            except Exception as e:
                self.logger.error(e)
                raise e

            # If the role has not already been granted...
            if not result or result[0] == 0:
                self.logger.info(f"Adding user {lowercase_user} to role {role_name}")
                try:
                    self.psql_cursor.execute(
                        f'GRANT "{role_name}" TO "{lowercase_user}"'
                    )
                    if self.is_citus:
                        self.psql_cursor.execute(
                            f"""
                        SELECT RUN_COMMAND_ON_WORKERS($CMD$ GRANT {role_name} TO {lowercase_user} $CMD$)
                        """
                        )
                except psycopg2.Error as e:
                    self.logger.error(e)
                    raise PSQLAuthnzPSQLException()
                except Exception as e:
                    self.logger.error(e)
                    raise e

    def synchronize_group(self, group: str, prefix: str, blacklist: list) -> bool:
        """Synchronize the membership between an LDAP group and a PostgreSQL role

        Args:
            group (str): Group to synchronize with
            prefix (str): prefix to search in role
            blacklist (list): List of users not allowed
        """

        try:
            group_name = group[1]["cn"][0]
            self.logger.info(f"{group[1].keys()}")
            group_members = group[1]["member"]
        except Exception as e:
            self.logger.error(f"Failed to retrieve group name and members: {e}")
            return False

        self.logger.debug(f"Group '{group_name}' has members: {group_members}")

        group_name = group_name.decode("utf-8")
        role_match = None
        role_name = None

        for p in prefix.split(','):
            role_match = re.search(f"^{p}(?P<role_name>[a-zA-Z0-9_]+)", group_name)

            if role_match:
                role_name = role_match.groups("role_name")[0]
                break

        if not role_name:
            self.logger.warning(
                f"Group '{group_name}' did not match any prefix pattern, skipping..."
            )
            return False

        if role_name in blacklist:
            self.logger.info(
                f"Skipping group '{group_name}' which is on the blacklist."
            )
            return False

        # First, ensure that the role exists
        try:
            role_name = role_name.lower()
            command = f"SElECT 1 FROM pg_roles WHERE rolname='{role_name}'"
            self.logger.info(command)
            self.psql_cursor.execute(command)
            result = self.psql_cursor.fetchone()
        except psycopg2.Error as e:
            self.logger.error(e)
            return False

        if not result or result[0] == 0:
            self.logger.warning(
                f"Group {group_name} does not have a PG role, skipping..."
            )
            return False

        # Second, extract each member from the list.
        try:
            authorized_users = self.extract_users(group_members)
        except Exception as e:
            self.logger.error(
                f"Failed to extract users from LDAP for {group_name}: {e}"
            )
            return False

        # Third, add authorized users to the role
        try:
            self.add_authorized_users(role_name, authorized_users)
        except Exception as e:
            self.logger.error(
                f"Failed to add users to the PG role for group {group_name}: {e}"
            )
            return False

        # Lastly, remove all users that are not on the list
        try:
            self.purge_unauthorized_users(role_name, authorized_users)
        except Exception as e:
            self.logger.error(
                f"Failed to remove unauthorized users from group {group_name}: {e}"
            )
            return False

        return True

    def synchronize(
        self, group_ou: str, group_class: str, domain: str, prefix: str, blacklist: list
    ):
        """Synchronizing function that initiates the entire process

        Args:
            group_ou (str): Group OU to target
            group_class (str): Group class to target for retrieval
            domain (str): Domain to target
            prefix (str): Prefix(es) to search on in the role
            blacklist (list): List of users to no include
        """
        self.logger.info(
            f"*** Synchronizing Postgres AuthNZ to {group_ou},{domain}. ***"
        )
        if self.is_citus:
            self.logger.debug("Running in Citus mode.")

        group_count = 0
        for group in self.get_groups(group_ou, group_class, domain):
            try:
                group_name = group[1]["cn"][0]
            except Exception as e:
                self.logger.error(f"Failed to get group name from {group}: {e}")

            self.logger.debug(f"Synchronizing group: {group_name}")

            if self.synchronize_group(group, prefix, blacklist):
                group_count += 1
            else:
                self.logger.error(f"Failed to syncronize group: {group_name}")

        self.logger.info(
            f"*** Successfully synchronized {group_count} group(s) from {group_ou},{domain} ***"
        )
