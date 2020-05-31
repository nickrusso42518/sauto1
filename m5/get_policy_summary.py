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
    fmc = CiscoFMC.build_from_env_vars()

    # Issue a GET request to collect a subset of access policies (just one
    # for now on the FMC device. Raise HTTPErrors if the request fails
    ap_url = "policy/accesspolicies"
    ap_resp = fmc.req(ap_url, params={"name": "AccePolicy-Test123"})

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

        # Get the rules within the policy by UUID
        rules_resp = fmc.req(f"{ap_url}/{policy['id']}/accessrules")

        # Iterate over the rules defined in the policy
        for rule in rules_resp["items"]:
            rule_resp = fmc.req(
                f"{ap_url}/{policy['id']}/accessrules/{rule['id']}"
            )
            print(f"  Rule name: {rule['name']} -> {rule_resp['action']}")

            # Print source/destination components, one line each. Unlike
            # FTD, the FMC doesn't have empty list values for each key
            for comp in components:
                present_comps = rule_resp.get(comp)
                if present_comps:
                    names = [item["name"] for item in present_comps["objects"]]
                    print(f"    {comp}: {','.join(names)}")


if __name__ == "__main__":
    main()
