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
        username="admin",
        password="Cisco1234",
        verify=False,
    ):
        """
        Constructor for the class. Takes in optional hostname/IP, username,
        password, and optional SSL verification setting. If left blank,
        the reservable DevNet sandbox will be used by default.
        """

        # Store all input parameters and assemble the base URL
        self.username = username
        self.password = password
        self.verify = verify
        self.api_path = f"https://{host}/api/fdm/latest"

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

        # Returns the first access policy configured on the device. FTD
        # only supports a single access policy (cannot create via API).
        # Store this ID for long-term use; benefits of stateful design
        self.policy_id = self.req("policy/accesspolicies")["items"][0]

    #
    # General management methods/utilities
    #

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

    #
    # Policy object management
    #

    def add_object(self, resource, obj_body):
        """
        Creates a new generic policy object given a resource URL string and
        complete object body.
        """

        # Issue a POST request, print a status message, and return response
        resp = self.req(resource, method="post", json=obj_body)
        print(f"Added {resp['type']} named {resp['name']} with ID {resp['id']}")
        return resp

    def deploy_group(self, group_dict):
        """
        Given a complete object group, deploy all objects in the group and
        the group itself, along with all proper group memberships.
        """

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
        """
        Simplifies deploying new object groups by reading in the HTTP body
        from JSON files. See "deploy_group" for logic.
        """
        with open(filename, "r") as handle:
            group_dict = json.load(handle)
        return self.deploy_group(group_dict)

    def purge_group_name(self, name, group_type):
        """
        Simplifies purging existing object groups and all their contained
        objects by specifying the group's name. See "purge_group_id"
        for logic.
        """
        group_url = URL_MAP[group_type]
        group = self.req(group_url, params={"filter": f"name:{name}"})

        # Presumably, only one item will be returned (can add more checks)
        if len(group["items"]) == 1:
            group_id = group["items"][0]["id"]
            print(f"Found {group_type} named {name} with ID {group_id}")
            return self.purge_group_id(group_id, group_type)

        return None

    def purge_group_id(self, group_id, group_type):
        """
        Deletes an existing object group and all of its contained objects
        for cleanup purposes. Requires the group ID and type as
        specified in the initial response when the group was created
        or collected.
        """

        # Get the proper URL for the group based on type, then collect the
        # group to get the list of objects inside
        group_url = URL_MAP[group_type]
        group = self.req(f"{group_url}/{group_id}")

        # Delete the group first and print a status message
        self.req(f"{group_url}/{group_id}", method="delete")
        print(f"Deleted {group_type} named {group['name']} with ID {group_id}")

        # Iterate over each object, find the proper URL, and delete the object
        for obj in group["objects"]:
            obj_url = URL_MAP[obj["type"]]
            self.req(f"{obj_url}/{obj['id']}", method="delete")
            print(
                f"Deleted {obj['type']} named {obj['name']} with ID {obj['id']}"
            )

    #
    # Policy rule management (full CRUD)
    #

    def get_access_rules(self, name=None):
        """
        Collects currently configured access rules. Specify an optional name
        to filter for a specific rule if desired.
        """

        # If name is defined, assemble a query params dict
        if name:
            params = {"filter": f"fts:{name}"}
        else:
            params = None
        resp = self.req(
            f"policy/accesspolicies/{self.policy_id}/accessrules", params=params
        )
        return resp

    def add_access_rule(self, rule_name, rule_action, rule_position, **kwargs):
        """
        Creates a new access rule given a set of core parameters and
        a variety of optional kwargs which map to rule options.
        """

        # Create the body based on positional and keyword arguments
        rule = {
            "name": rule_name,
            "ruleAction": rule_action,
            "rulePosition": rule_position,
            "type": "accessrule",
        }
        rule.update(kwargs)

        # Optional debugging to view the completed VPN access rule
        # print(json.dumps(rule, indent=2))

        # Issue a POST request to add the access rule and return the reponse
        resp = self.req(
            f"policy/accesspolicies/{self.policy_id}/accessrules",
            method="post",
            json=rule,
        )
        return resp

    def update_access_rule(self, rule_id, **kwargs):
        """
        Updates an existing access rule given the rule's ID and
        a variety of optional kwargs which map to rule options.
        """

        # Assemble the URL and issue a GET request to get the rule details
        url = f"policy/accesspolicies/{self.policy_id}/accessrules/{rule_id}"
        rule = self.req(url)

        # Update the rule response with new kwargs, overwriting duplicates
        rule.update(kwargs)

        # Optional debugging to view the completed VPN access rule
        # print(json.dumps(rule, indent=2))

        # Issue a POST request to update the access rule and return the reponse
        resp = self.req(url, method="put", json=rule)
        return resp

    def delete_access_rule_name(self, name):
        """
        Simplifies deleting access rules by allowing a name to be specified.
        See "delete_access_rule_id" for logic.
        """
        resp = self.get_access_rules(name)

        # Presumably, only one item will be returned (can add more checks)
        if len(resp["items"]) == 1:
            rule_id = resp["items"][0]["id"]
            print(f"Found accessrule named {name} with ID {rule_id}")
            return self.delete_access_rule_id(rule_id)

        return None

    def delete_access_rule_id(self, rule_id):
        """
        Deletes an existing access rule by ID and returns the response.
        """
        resp = self.req(
            f"policy/accesspolicies/{self.policy_id}/accessrules/{rule_id}",
            method="delete",
        )
        print(f"Deleted accessrule with ID {rule_id}")
        return resp

    def get_security_zones(self, name=None):
        """
        Returns the current security zones with an optional name filter.
        If name is not specified, all zones are returned
        """

        # If name is defined, assemble a query params dict
        if name:
            params = {"filter": f"name:{name}"}
        else:
            params = None

        resp = self.req("object/securityzones", params=params)
        return resp

    #
    # Intrusion Prevention System (IPS) policy management
    #

    def get_ips_policy(self, name=None):
        """
        Returns the list of IPS policies on the device. Specify an optional
        "name" keyword argument to filter for a specific item.
        """

        # If name is defined, assemble a query params dict
        if name:
            params = {"filter": f"name:{name}"}
        else:
            params = None

        # Issue a GET request and return the result
        resp = self.req("policy/intrusionpolicies", params=params)
        return resp

    def activate_threat_license(self):
        """
        IPS policy application in FTD requires the THREAT license.
        This method idempotently activates the threat license.
        """

        # Get the list of current licenses
        lics = self.req("license/smartlicenses")

        # Check all licenses to see if THREAT is activated. If so,
        # return that license
        for lic in lics["items"]:
            if lic["licenseType"].lower() == "threat":
                return lic

        # Threat license not activated, activate it by defining
        # the HTTP body below
        body = {
            "compliant": True,
            "count": 1,
            "licenseType": "THREAT",
            "type": "license",
        }

        # Issue an HTTP POST request to activate the license
        resp = self.req("license/smartlicenses", method="post", json=body)
        return resp

    #
    # Policy deployment and history
    # TODO


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
