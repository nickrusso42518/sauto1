#!/usr/bin/env python

"""
Author: Nick Russo
Purpose: Gets the current policy objects from the FMC sandbox.
Check out the API explorer at "https://<fmc_host>/api/api-explorer"
"""

from cisco_fmc import CiscoFMC


def main():
    """
    Execution begins here.
    """

    # Create a new FMC object referencing the DevNet sandbox (default)
    fmc = CiscoFMC()

    # Issue a GET request to collect a list of network objects configured
    # on the FMC device. Raise HTTPErrors if the request fails
    ap_resp = fmc.req("policy/accesspolicies")

    # Each rule has at least these 6 lists for src/dest zones,
    # networks, and ports. Identify the REST resources here
    components = [
        "sourceZones",
        "destinationZones",
        "sourceNetworks",
        "destinationNetworks",
        "sourcePorts",
        "destinationPorts",
    ]

    # Iterate over all of the access policies (typically only one)
    for policy in ap_resp["items"]:
        print(f"Policy name: {policy['name']}")

        # Get the rules within the policy by UUID
        rule_resp = fmc.req(f"policy/accesspolicies/{policy['id']}/accessrules")

        # Iterate over the rules defined in the policy
        for rule in rule_resp["items"]:
            print(f"  Rule name: {rule['name']} -> {rule['ruleAction']}")

            # Print source/destination components, one line each
            for comp in components:
                names = [item["name"] for item in rule[comp]]

                # Only print the data if it exists; ignore empty lists
                if names:
                    print(f"    {comp}: {','.join(names)}")


if __name__ == "__main__":
    main()
