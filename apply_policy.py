#!/usr/bin/env python

"""
Author: Nick Russo
Purpose: Applies the polic described in the "policy_objects" files.
Check out the API explorer at "https://<ftd_host>/#/api-explorer"
"""

import os
import json
import requests
from glob import glob
from cisco_ftd import CiscoFTD


def main():
    """
    Execution begins here.
    """

    # Create a new FTD object referencing the DevNet sandbox (default)
    ftd = CiscoFTD()
    

    #print(json.dumps(create_policy_objects(ftd, "networks"), indent=2))
    #print(json.dumps(create_policy_objects(ftd, "udpports"), indent=2))
    #print(json.dumps(create_policy_objects(ftd, "protocols"), indent=2))


    # this whole thing is a mess
    # need to figure out right way to add objects and groups
    # without too much copy/paste

    build_objects(glob("objects/test*.json"), "objects/group_blacklist.json")

    # apply/deploy
    # update with IPS policy

def build(ftd, obj_files, group_file):
    for filename in obj_files:
        with open(filename) as handle:
            data = json.load(handle)
            resp = ftd.req(f"object/{resource}", method="post", json=data)
            print(f"Added {resource} object {data['name']} with ID {resp['id']}")
    

def create__object_group(ftd, filename):
    directory = "policy_objects"
    with open(f"{directory}/{filename}") as handle:
        data = json.load(handle)
        resp = ftd.req(f"object/{resource}", method="post", json=data)
        print(f"Added {resource} object {data['name']} with ID {resp['id']}")
    

def create_policy_objects(ftd, resource):

    created_objects = []
    directory = f"policy_objects/{resource}"
    for filename in os.listdir(directory):
        with open(f"{directory}/{filename}") as handle:
            data = json.load(handle)
            resp = ftd.req(f"object/{resource}", method="post", json=data)
            print(f"Added {resource} object {data['name']} with ID {resp['id']}")

            # These keys are necessary for adding objects to groups later
            important_keys = ["name", "version", "id", "type"]

            # Use a dictionary comprehension to get a sub-dictionary of
            # the response data containing only the important keys
            created_object = {key: resp[key] for key in important_keys}

            # Add the sub-dictionary to the list of created objects
            created_objects.append(created_object)

    # Return the list of created objects when "for" loop completes
    return created_objects


if __name__ == "__main__":
    main()
