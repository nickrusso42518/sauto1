#!/usr/bin/env python

"""
Author: Nick Russo
Purpose: Python client SDK for Cisco FMC.
Check out the API explorer at "https://<fmc_host>/api/api-explorer"
"""

import os
import json
import time
import requests


# Maps the type of an object to the API resource string
URL_MAP = {
    "Host": "object/hosts",
    "Network": "object/networks",
    "NetworkGroup": "object/networkgroups",
    "ProtocolPortObject": "object/protocolportobjects",
    "PortObjectGroup": "object/portobjectgroups",
}


class CiscoFMC:
    """
    Python client SDK for Cisco FMC.
    """

    def __init__(
        self,
        username,
        password,
        host="fmcrestapisandbox.cisco.com",
        verify=False,
    ):
        """
        Constructor for the class. Takes in optional hostname/IP, username,
        password, and optional SSL verification setting. If left blank,
        the reservable DevNet sandbox will be used by default for the host.
        but the username/password change for each reservation.
        """

        # Store all input parameters and assemble the base URL
        self.username = username
        self.password = password
        self.verify = verify
        self.base_url = f"https://{host}/api"

        # If we aren't verifying SSL certificates, disable obnoxious warnings
        if not self.verify:
            requests.packages.urllib3.disable_warnings()

        # Create a stateful HTTPS session to improve performance
        self.sess = requests.session()

        # Perform initial authentication, which also generates the API path
        # and reusable HTTP header dictionary
        self.authenticate("generatetoken")

    #
    # General management methods/utilities
    #

    @staticmethod
    def build_from_env_vars():
        """
        Static class-level helper method to quickly create a new CiscoFMC
        object using environment variables:
          1. FMC_USERNAME: Your personal username for FMC
          2. FMC_PASSWORD: Your personal password for FMC
        """

        # Collect username and password (required) from env vars
        username = os.environ.get("FMC_USERNAME")
        if not username:
            raise ValueError("Must define FMC_USERNAME environment var")

        password = os.environ.get("FMC_PASSWORD")
        if not password:
            raise ValueError("Must define FMC_PASSWORD environment var")

        # Specifying the host is optional; defaults to DevNet sandbox
        host = os.environ.get("FMC_HOST", "fmcrestapisandbox.cisco.com")

        # Create and return new CiscoFMC object
        return CiscoFMC(username=username, password=password, host=host)

    def reauthenticate(self):
        """
        Uses the 'refresh_token' to reauthenticate the session to FMC.
        """
        self.authenticate("refreshtoken")

    def authenticate(self, grant_type):
        """
        Perform authentication, either "generatetoken" or "refreshtoken", and retain the new
        tokens as attributes of the object.
        """

        # Construct the proper auth URL based on the grant type. Notice that
        # this URL uses "fmc_platform" vs the more common "fmc_config"
        auth_url = f"{self.base_url}/fmc_platform/v1/auth/{grant_type}"

        # Issue the POST request using either basic auth or the API token.
        # Be sure to ignore SSL cert checking in the FMC sandbox.
        if grant_type == "generatetoken":
            token_resp = self.sess.post(
                auth_url,
                auth=(self.username, self.password),
                verify=self.verify,
            )
        elif grant_type == "refreshtoken":
            token_resp = self.sess.post(
                auth_url, headers=self.headers, verify=self.verify
            )
        token_resp.raise_for_status()

        # Create the common headers from this point forward; technically
        # the refresh token isn't necessary for non-refresh calls, but
        # easier to store it here than in a separate attribute
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-auth-access-token": token_resp.headers["X-auth-access-token"],
            "X-auth-refresh-token": token_resp.headers["X-auth-refresh-token"],
        }

        # Next, define the base URL, which includes the common domain ID.
        # You can access this using the "global" or "DOMAIN_UUID" key.
        # This is part of the URL for many requests in the future
        domain_id = token_resp.headers["global"]
        self.api_path = f"{self.base_url}/fmc_config/v1/domain/{domain_id}"

    def req(self, resource, method="get", **kwargs):
        """
        Execute an arbitrary HTTP request by supplying a resource without
        a leading slash to be appended to the base URL. Any other keyword
        arguments supported by 'requests.request' are supported here,
        such as data, json, files, params, etc.
        """

        # Issue the general request based on method arguments
        resp = self.sess.request(
            url=f"{self.api_path}/{resource}",
            method=method,
            headers=self.headers,
            verify=self.verify,
            **kwargs,
        )

        # Optional debugging to view the response body if it exists
        # if resp.text:
        #    print(json.dumps(resp.json(), indent=2))

        # Ensure the request succeeded
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

    def add_group(self, group_dict):
        """
        Given a complete object group, create all objects in the group and
        the group itself, along with all proper group memberships.
        """

        # Cannot create empty groups, so build objects individually first
        for obj_body in group_dict["objects"]:
            obj_url = URL_MAP[obj_body["type"]]
            obj_resp = self.add_object(obj_url, obj_body)

            # Add a new "id" key with the ID returned and
            # remove "value" key if it exists (it always should)
            obj_body["id"] = obj_resp["id"]
            obj_body.pop("value", None)

        # All objects built; update the group's "objects" key
        group_url = URL_MAP[group_dict["type"]]
        group_resp = self.add_object(group_url, group_dict)

        # Return the group response which will contain all UUIDs
        return group_resp

    def add_group_file(self, filename):
        """
        Simplifies adding new object groups by reading in the HTTP body
        from JSON files. See "add_group" for logic.
        """
        with open(filename, "r") as handle:
            group_dict = json.load(handle)
        return self.add_group(group_dict)

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
    # Policy rule management
    #

    def add_access_policy(self, name, description="na", default_action="BLOCK"):
        """
        Creates a new access policy given a set of core parameters. The
        "default_action" defaults to "BLOCK" but can also be "TRUST".
        """

        # Create the HTTP body
        policy = {
            "name": name,
            "description": description,
            "defaultAction": {
                "type": "AccessPolicyDefaultAction",
                "action": default_action,
            },
        }

        # Issue an HTTP POST request to create a new access policy
        resp = self.req("policy/accesspolicies", method="post", json=policy)
        print(f"Added accesspolicy named {name} with ID {resp['id']}")
        return resp

    def add_access_rule(self, name, action, policy_id, **kwargs):
        """
        Creates a new access rule given a set of core parameters and
        a variety of optional kwargs which map to rule options. This
        method will strip down full object dictionaries that come from
        other responses to include only the fields that FMC needs.
        """

        # Create the body based on positional and keyword arguments
        rule = {
            "name": name,
            "enabled": True,
            "action": action,
            "type": "AccessRule",
        }

        # FMC appears to only accept name, id and type keys; cannot add
        # entire kwarg response dictionaries to the HTTP body
        for key, value in kwargs.items():

            # If there is an "objects" key
            if value.get("objects"):
                # Create a new list for each kwarg to contain the stripped objects
                new_obj_list = []
                for obj in value["objects"]:

                    # Add a new stripped object to the list
                    new_obj_list.append(
                        {
                            "name": obj["name"],
                            "type": obj["type"],
                            "id": obj["id"],
                        }
                    )

                # Stripped objects completed; update the rule at the proper key
                rule[key] = {"objects": new_obj_list}

            # There is no "objects" key; just strip the existing dictionary
            else:
                rule[key] = {
                    "name": value["name"],
                    "type": value["type"],
                    "id": value["id"],
                }

        # Issue a POST request to add the access rule and return the reponse
        resp = self.req(
            f"policy/accesspolicies/{policy_id}/accessrules",
            method="post",
            json=rule,
        )
        print(f"Added accessrule named {name} with ID {resp['id']}")
        return resp

    def delete_access_policy(self, policy_id):
        """
        Deletes an existing access policy by ID and returns the response.
        This also deletes all access rules within the access policy.
        """
        resp = self.req(f"policy/accesspolicies/{policy_id}", method="delete")
        print(f"Deleted accesspolicy with ID {policy_id}")
        return resp

    def get_security_zones(self, name=None):
        """
        Returns the current security zones with an optional name filter.
        If name is not specified, all zones are returned.
        """

        # The "expanded" query param reveals the entire object
        # when collecting a list; can reduce follow-on requests
        params = {"expanded": True}

        # If name is defined, add a "name" key to search for a specific item
        if name:
            params["name"] = name

        # Issue an HTTP GET request to collect the security zone(s)
        resp = self.req("object/securityzones", params=params)
        return resp

    #
    # Intrusion Prevention System (IPS) policy management
    #

    def get_ips_policies(self, name=None):
        """
        Returns the current IPS policies with an optional name filter.
        If name is not specified, all IPS policies are returned.
        """

        # Issue an HTTP GET request to collect the IPS policies
        # using a larger "limit" to improve chances of finding the policy
        resp = self.req("policy/intrusionpolicies", params={"limit": 100})

        # Name filtering is not supported, so iterate through the items and
        # check each one for a match. If there is a match, update the "items"
        # key to contain a list of one value for consistency
        if name:
            for obj in resp["items"]:
                if obj["name"].lower() == name.lower():
                    resp["items"] = [obj]
                    break

        # Name was not specified or not found; return all IPS policies
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
    # Policy deployment
    #

    def deploy_changes(self):
        """
        Deploys changed to the device (operationalizes the policy
        updates so they take effect). Returns the final response
        from the last "get" action that checks the status as
        this method waits until the deployment is complete (synchronous).
        """

        # Issue a POST request with no body to begin deployment
        url = "operational/deploy"
        deploy_resp = self.req(url, method="post")

        # Extract the deploymnt ID and current end time. The
        # end time will be -1 until the process completes. Could
        # also use "state" but I cannot find a definitive list
        # of all states, so this is harder to use
        deploy_id = deploy_resp["id"]
        deploy_end = deploy_resp["endTime"]

        # While the end time remains negative, the deployment has
        # not completed; keep looping
        while deploy_end < 0:

            # After a short wait, query the specific deployment
            # by ID and store the end time again. If positive,
            # that's a good indication the deployment is complete
            print(f"Deployment {deploy_id} in process: {deploy_resp['state']}")
            time.sleep(10)
            deploy_resp = self.req(f"{url}/{deploy_id}")
            deploy_end = deploy_resp["endTime"]

        # Deployment ended (success or failure); return the final state
        print(f"Deployment {deploy_id} complete: {deploy_resp['state']}")
        return deploy_end


def main():
    """
    Quickly test the FMC class authentication capabilities.
    """

    # Create a new FMC object, which performs initial auth; show the tokens
    fmc = CiscoFMC.build_from_env_vars()
    print(fmc.headers["X-auth-access-token"])
    print(fmc.headers["X-auth-refresh-token"])

    # Reauthenticate using the refresh token; show the tokens
    fmc.reauthenticate()
    print(fmc.headers["X-auth-access-token"])
    print(fmc.headers["X-auth-refresh-token"])


if __name__ == "__main__":
    main()
