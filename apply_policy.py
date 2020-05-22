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

    del_id = "c298068b-9c6e-11ea-a321-f167548d026f"
    #ftd.req(f"object/networks/{del_id}", method="delete")
    
    # Create VPN network, IPsec port/protocol, and blacklist network groups
    vpn_resp = ftd.deploy_group_file("policy/group_vpn.json")
    ipsec_resp = ftd.deploy_group_file("policy/group_ipsec.json")
    blacklist_resp = ftd.deploy_group_file("policy/group_blacklist.json")




if __name__ == "__main__":
    main()
