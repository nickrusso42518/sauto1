#!/usr/bin/env python

"""
Author: Nick Russo
Purpose: Gets the current policy objects from the FTD sandbox.
Check out the API explorer at "https://<ftd_host>/#/api-explorer"
"""

import requests
from cisco_ftd import CiscoFTD


def main():
    """
    Execution begins here.
    """

    # Create a new FTD object referencing the DevNet sandbox (default)
    ftd = CiscoFTD()

    # Issue a GET request to collect a list of network objects configured
    # on the FTD device. Raise HTTPErrors if the request fails
    ap_resp = ftd.req("policy/accesspolicies")

    # Iterate over all of the access policies (typically only one)
    for policy in ap_resp["items"]:
        print(f"Policy name: {policy['name']}")

        # Get the rules within the policy by UUID
        rule_path = f"policy/accesspolicies/{policy['id']}/accessrules"
        rule_resp = ftd.req(rule_path)

        # Iterate over the rules defined in the policy
        for rule in rule_resp["items"]:
            print(f"  Rule name: {rule['name']} -> {rule['ruleAction']}")

            print_security_zones(ftd, rule)
            print_networks(ftd, rule)
            print_ports_protocols(ftd, rule)


def print_security_zones(ftd, rule):
    for zone_type in ["sourceZones", "destinationZones"]:

        # If there are no elements, don't print headers, loop again
        if not rule[zone_type]:
            continue

        print(f"    Zone type: {zone_type}")
        for zone in rule[zone_type]:
            data = ftd.req(f"object/securityzones/{zone['id']}")
            print(f"      Zone name: {data['name']}")
            for intf in data["interfaces"]:
                print(f"        Intf: {intf['name']} / {intf['hardwareName']}")


def print_networks(ftd, rule):
    for net_type in ["sourceNetworks", "destinationNetworks"]:

        # If there are no elements, don't print headers, loop again
        if not rule[net_type]:
            continue

        print(f"    Network group type: {net_type}")
        for net in rule[net_type]:
            data = ftd.req(f"object/networkgroups/{net['id']}")
            print(f"      Network group name: {data['name']}")
            for obj in data["objects"]:
                detail = ftd.req(f"resource/{obj['id']}")
                print(f"        Network: {detail['name']} / {detail['value']}")


def print_ports_protocols(ftd, rule):
    for port_type in ["sourcePorts", "destinationPorts"]:

        # If there are no elements, don't print headers, loop again
        if not rule[port_type]:
            continue

        print(f"    Port group type: {port_type}")
        for port in rule[port_type]:
            data = ftd.req(f"object/portgroups/{port['id']}")
            print(f"      Port group name: {data['name']}")
            for obj in data["objects"]:

                if obj["type"].lower() == "tcpportobject":
                    resource, key == "object/tcpports", "port"
                elif obj["type"].lower() == "udpportobject":
                    resource, key == "object/udpports", "port"
                elif obj["type"].lower() == "protocolobject":
                    resource, key = "object/protocols", "protocol"

                detail = ftd.req(f"resource/{obj['id']}")
                print(f"        Port/Proto: {detail['name']} / {detail[key]}")


if __name__ == "__main__":
    main()
