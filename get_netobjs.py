#!/usr/bin/env python

"""
Author: Nick Russo
Purpose: Gets the current policy objects from the FTD sandbox.
Check out the API explorer at "https://<ftd_host>/#/api-explorer"
"""

import requests
from auth_token import get_token


def main():
    """
    Execution begins here.
    """

    # The FTD sandbox uses a self-signed cert at present, so let's ignore any
    # obvious security warnings for now.
    requests.packages.urllib3.disable_warnings()

    # The API path below is what the DevNet sandbox uses for API testing,
    # which may change in the future. Be sure to check the IP address as
    # I suspect this changes frequently. See here for more details:
    # https://developer.cisco.com/firepower/
    api_path = "https://10.10.20.65/api/fdm/latest"
    token = get_token(api_path)

    # To authenticate, we issue a POST request with our username/password
    # as a JSON body to obtain a bearer token in response.
    get_headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
    }

    # List of resources to query; basically, network and port/protocol objects
    # The second item in the tuple is the "value of interest" which varies
    resource_list = [
        ("object/networks", "value"),
        ("object/networkgroups", None),
        ("object/tcpports", "port"),
        ("object/udpports", "port"),
        ("object/protocols", "protocol"),
        ("object/portgroups", None),
    ]

    # Iterate over the list of specified resource/key tuples
    for resource, key in resource_list:

        # Issue a GET request to collect a list of network objects configured
        # on the FTD device. Raise HTTPErrors if the request fails
        get_resp = requests.get(
            f"{api_path}/{resource}", headers=get_headers, verify=False
        )
        get_resp.raise_for_status()

        # Iterate over each item in the "items" list returned by the API
        for item in get_resp.json()["items"]:

            # Print the name, type, and "value of interest" for
            # each item in the list if the key is defined/truthy
            print(f"\nName: {item['name']} / {item['type']}")
            if key:
                print(f"{key}: {item[key]}")

            # If the "objects" key is present and is a list,
            # iterate over that list and print the name of each object
            if "objects" in item and isinstance(item["objects"], list):
                print("Contained objects:")
                for obj in item["objects"]:
                    print(f"  - {obj['name']}")


if __name__ == "__main__":
    main()
