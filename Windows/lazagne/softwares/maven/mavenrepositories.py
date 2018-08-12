# -*- coding: utf-8 -*-
import os
from xml.etree import ElementTree

from lazagne.config.constant import constant
from lazagne.config.module_info import ModuleInfo


class MavenRepositories(ModuleInfo):

    def __init__(self):
        ModuleInfo.__init__(self, 'mavenrepositories', 'maven')
        # Interesting XML nodes in Maven repository configuration
        self.nodes_to_extract = ["id", "username", "password", "privateKey", "passphrase"]
        self.settings_namespace = "{http://maven.apache.org/SETTINGS/1.0.0}"

    def extract_master_password(self):
        """
        Detect if a Master password exists and then extract it.

        See https://maven.apache.org/guides/mini/guide-encryption.html#How_to_create_a_master_password

        :return: The master password value or None if no master password exists.
        """
        master_password = None
        master_password_file_location = constant.profile["USERPROFILE"] + u'\\.m2\\settings-security.xml'
        if os.path.isfile(master_password_file_location):
            try:
                config = ElementTree.parse(master_password_file_location).getroot()
                master_password_node = config.find(".//master")
                if master_password_node is not None:
                    master_password = master_password_node.text
            except Exception as e:
                self.error(u"Cannot retrieve master password '%s'" % e)
                master_password = None

        return master_password

    def extract_repositories_credentials(self):
        """
        Extract all repositories's credentials.

        See https://maven.apache.org/settings.html#Servers

        :return: List of dict in which one dict contains all information for a repository.
        """
        repos_creds = []
        maven_settings_file_location = constant.profile["USERPROFILE"] + u'\\.m2\\settings.xml'
        if os.path.isfile(maven_settings_file_location):
            try:
                settings = ElementTree.parse(maven_settings_file_location).getroot()
                server_nodes = settings.findall(".//%sserver" % self.settings_namespace)
                for server_node in server_nodes:
                    creds = {}
                    for child_node in server_node:
                        tag_name = child_node.tag.replace(self.settings_namespace, "")
                        if tag_name in self.nodes_to_extract:
                            creds[tag_name] = child_node.text.strip()
                    if len(creds) > 0:
                        repos_creds.append(creds)
            except Exception as e:
                self.error(u"Cannot retrieve repositories credentials '%s'" % e)

        return repos_creds

    def use_key_auth(self, creds_dict):
        """
        Utility function to determine if a repository use private key authentication.

        :param creds_dict: Repository credentials dict
        :return: True only if the repositry use private key authentication
        """
        state = False
        if "privateKey" in creds_dict:
            pk_file_location = creds_dict["privateKey"]
            pk_file_location = pk_file_location.replace("${user.home}", constant.profile["USERPROFILE"])
            state = os.path.isfile(pk_file_location)

        return state

    def run(self):
        """
        Main function:

        - For encrypted password, provides the encrypted version of the password with the master password in order
        to allow "LaZagne run initiator" the use the encryption parameter associated with the version of Maven because
        encryption parameters can change between version of Maven.

        - "LaZagne run initiator" can also use the encrypted password and the master password "AS IS"
        in a Maven distribution to access repositories.
        See:
        github.com/jelmerk/maven-settings-decoder
        github.com/sonatype/plexus-cipher/blob/master/src/main/java/org/sonatype/plexus/components/cipher/PBECipher.java
        """

        # Extract the master password
        master_password = self.extract_master_password()

        # Extract all available repositories credentials
        repos_creds = self.extract_repositories_credentials()

        # Parse and process the list of repositories's credentials
        # 3 cases are handled:
        # => Authentication using password protected with the master password (encrypted)
        # => Authentication using password not protected with the master password (plain text)
        # => Authentication using private key
        pwd_found = []
        for creds in repos_creds:
            values = {
                "Id": creds["id"],
                "Login": creds["username"]
            }
            if not self.use_key_auth(creds):
                pwd = creds["password"].strip()
                # Case for authentication using password protected with the master password
                if pwd.startswith("{") and pwd.endswith("}"):
                    values["SymetricEncryptionKey"] = master_password
                    values["PasswordEncrypted"] = pwd
                else:
                    values["Password"] = pwd
            else:
                # Case for authentication using private key
                pk_file_location = creds["privateKey"]
                pk_file_location = pk_file_location.replace("${user.home}", constant.profile["USERPROFILE"])
                with open(pk_file_location, "r") as pk_file:
                    values["PrivateKey"] = pk_file.read()
                if "passphrase" in creds:
                    values["Passphrase"] = creds["passphrase"]
            pwd_found.append(values)

        return pwd_found
