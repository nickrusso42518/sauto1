#!/usr/bin/env python

"""
Author: Nick Russo
Purpose: Applies the polic described in the "policy_objects" files.
Check out the API explorer at "https://<ftd_host>/#/api-explorer"
"""

from cisco_ftd import CiscoFTD


def main():
    """
    Execution begins here.
    """

    # Create a new FTD object referencing the DevNet sandbox (default)
    ftd = CiscoFTD()

    # Create VPN network, IPsec port/protocol, and blacklist network groups
    vpn_resp = ftd.deploy_group_file("policy/group_vpn.json")
    ipsec_resp = ftd.deploy_group_file("policy/group_ipsec.json")
    blacklist_resp = ftd.deploy_group_file("policy/group_blacklist.json")

    # Optional cleanup tasks; useful for testing to save time
    ftd.purge_group_name("NETG_VPN_CONCENTRATORS", "networkobjectgroup")
    ftd.purge_group_name("NETG_BLACKLIST", "networkobjectgroup")
    ftd.purge_group_name("PORTG_IPSEC", "portobjectgroup")


if __name__ == "__main__":
    main()
