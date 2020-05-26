#!/usr/bin/env python

"""
Author: Nick Russo
Purpose: Applies the policy described in the "policy_objects" files.
Check out the API explorer at "https://<fmc_host>/api/api-explorer"
"""

from cisco_fmc import CiscoFMC


def main():
    """
    Execution begins here.
    """

    # Create a new FMC object referencing the DevNet sandbox (default)
    fmc = CiscoFMC.build_from_env_vars()

    # Optional cleanup tasks; useful for testing to save time
    cleanup(fmc)

    # import pdb; pdb.set_trace()

    # Create VPN network, IPsec port/protocol, and blacklist network groups
    vpn_resp = fmc.add_group_file("objects/group_vpn.json")
    fmc.purge_group_id(vpn_resp["id"], "NetworkGroup")

    blacklist_resp = fmc.add_group_file("objects/group_blacklist.json")
    fmc.purge_group_id(blacklist_resp["id"], "NetworkGroup")

    ipsec_resp = fmc.add_group_file("objects/group_ipsec.json")
    fmc.purge_group_id(ipsec_resp["id"], "PortObjectGroup")

def cleanup(fmc):
    pass

if __name__ == "__main__":
    main()
