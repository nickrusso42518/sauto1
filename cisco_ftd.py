#!/usr/bin/env python

"""
Author: Nick Russo
Purpose: Python client SDK for Cisco FTD.
Check out the API explorer at "https://<ftd_host>/#/api-explorer"
"""

import json
import requests

# Maps the type of an object to the API resource string
URL_MAP = {
    "networkobject": "object/networks",
    "networkobjectgroup": "object/networkgroups",
    "tcpportobject": "object/tcpports",
    "udpportobject": "object/udpports",
    "protocolobject": "object/protocols",
    "portobjectgroup": "object/portgroups",
}

class CiscoFTD:
    """
    Python client SDK for Cisco FTD.
    """

    def __init__(
        self,
        host="10.10.20.65",
        port=443,
        username="admin",
        password="Cisco1234",
        verify=False,
    ):
        """
        Constructor for the class. Takes in optional host, port, username,
        password, and optional SSL verification setting. If left blank,
        the reservable DevNet sandbox will be used by default.
        """

        # Store all input parameters and assemble the base URL
        self.username = username
        self.password = password
        self.verify = verify
        self.api_path = f"https://{host}:{port}/api/fdm/latest"

        # If we aren't verifying SSL certificates, disable obnoxious warnings
        if not self.verify:
            requests.packages.urllib3.disable_warnings()

        # Create a stateful HTTPS session to improve performance
        self.sess = requests.session()

        # To authenticate, we issue a POST request with our username/password
        # as a JSON body to obtain a bearer token in response. These headers
        # are reusable because almost all API interactions use JSON
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        # Perform initial authentication
        self.authenticate("password")

    def reauthenticate(self):
        """
        Uses the 'refresh_token' to reauthenticate the session to FTD.
        """
        self.authenticate("refresh_token")

    def authenticate(self, grant_type):
        """
        Perform authentication, either initial or refresh, and retain the new
        tokens as attributes of the object.
        """

        # This is the JSON payload included in the initial POST request to
        # obtain a bearer token.
        token_data = {"grant_type": grant_type}
        if grant_type == "refresh_token":
            token_data["refresh_token"] = self.refresh_token
        elif grant_type == "password":
            token_data.update(
                {"username": self.username, "password": self.password}
            )

        # Issue the POST request to the proper URL with the predefined headers
        # and body dictionaries. Be sure to ignore SSL cert checking as this
        # is a standalone sandbox FTD instance.
        token_resp = self.sess.post(
            f"{self.api_path}/fdm/token",
            headers=self.headers,
            json=token_data,
            verify=self.verify,
        )
        token_resp.raise_for_status()

        # We've obtained the token data; extract the critical values
        token_data = token_resp.json()
        self.access_token = token_data["access_token"]
        self.refresh_token = token_data["refresh_token"]

        # Update the headers dictionary with the new access token
        self.headers["Authorization"] = f"Bearer {self.access_token}"

    def req(self, resource, method="get", **kwargs):
        """
        Execute an arbitrary HTTP request by supplying a resource without
        a leading slash to be appended to the base URL. Any other keyword
        arguments supported by 'requests.request' are supported here,
        such as data, json, files, params, etc.
        """
        resp = self.sess.request(
            url=f"{self.api_path}/{resource}",
            method=method,
            headers=self.headers,
            verify=self.verify,
            **kwargs,
        )
        resp.raise_for_status()

        # If body exists, turn to JSON and return; Else, return empty dict
        if resp.text:
            return resp.json()

        return {}

                
    def add_object(self, resource, obj_body):

        # Issue a POST request and print a status message
        resp = self.req(resource, method="post", json=obj_body)
        print(f"Added {resp['type']} named {resp['name']} with ID {resp['id']}")
        return resp

        #important_keys = ["name", "version", "id", "type"]
        #created_object = {key: resp[key] for key in important_keys}
        #return created_object
        

    def deploy_group(self, group_dict):

        # Cannot create empty groups, so build objects individually first
        created_objects = []
        for obj_body in group_dict["objects"]:
            obj_url = URL_MAP[obj_body["type"]]
            obj_resp = self.add_object(obj_url, obj_body)

            # Add the response to a list to replace the group "objects"
            created_objects.append(obj_resp)

        # All objects built; update the group's "objects" key
        group_dict["objects"] = created_objects
        group_url = URL_MAP[group_dict["type"]]
        group_resp = self.add_object(group_url, group_dict)

        # Return the group response which will contain all UUIDs
        return group_resp


    def deploy_group_file(self, filename):
        with open(filename, "r") as handle:
            group_dict = json.load(handle)
        return self.deploy_group(group_dict)



def main():
    """
    Quickly test the FTD class authentication capabilities.
    """

    # Create a new FTD object, which performs initial auth; show the tokens
    ftd = CiscoFTD()
    print(ftd.access_token)
    print(ftd.refresh_token)

    # Reauthenticate using the refresh token; show the tokens
    ftd.reauthenticate()
    print(ftd.access_token)
    print(ftd.refresh_token)


if __name__ == "__main__":
    main()
