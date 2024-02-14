#!/usr/bin/python
# CS 6250 Spring 2023- SDN Firewall Project with POX
# build hackers-44

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.revent import *
from pox.lib.addresses import IPAddr, EthAddr

# You may use this space before the firewall_policy_processing function to add any extra function that you 
# may need to complete your firewall implementation.  No additional functions "should" be required to complete
# this assignment.


def firewall_policy_processing(policies):
    '''
    This is where you are to implement your code that will build POX/Openflow Match and Action operations to
    create a dynamic firewall meeting the requirements specified in your configure.pol file.  Do NOT hardcode
    the IP/MAC Addresses/Protocols/Ports that are specified in the project description - this code should use
    the values provided in the configure.pol to implement the firewall.

    The policies passed to this function is a list of dictionary objects that contain the data imported from the
    configure.pol file.  The policy variable in the "for policy in policies" represents a single line from the
    configure.pol file.  Each of the configuration values are then accessed using the policy['field'] command. 
    The fields are:  'rulenum','action','mac-src','mac-dst','ip-src','ip-dst','ipprotocol','port-src','port-dst',
    'comment'.

    Your return from this function is a list of flow_mods that represent the different rules in your configure.pol file.

    Implementation Hints:
    The documentation for the POX controller is available at https://noxrepo.github.io/pox-doc/html .  This project
    is using the gar-experimental branch of POX in order to properly support Python 3.  To complete this project, you
    need to use the OpenFlow match and flow_modification routines (https://noxrepo.github.io/pox-doc/html/#openflow-messages
    for flow_mod and https://noxrepo.github.io/pox-doc/html/#match-structure for match.)  Also, do NOT wrap IP Addresses with
    IPAddr() unless you reformat the CIDR notation.  Look at the https://github.com/att/pox/blob/master/pox/lib/addresses.py
    for what POX is expecting as an IP Address.
    '''

    rules = []

    for policy in policies:
        # Enter your code here to implement matching and block/allow rules.  See the links
        # in Implementation Hints on how to do this. 
        # HINT:  Think about how to use the priority in your flow modification.

        # Traffic to 192.168.101.101:80 should be sent out switch port 4

        #print("I am here: ", policy)

        #create an openFlow flow modification object
        rule=of.ofp_flow_mod()
        
        #create a POX packet matching object
        matchobj = of.ofp_match()

        if policy['mac-src'] and (policy['mac-src'] != '-'):
            matchobj.dl_src=EthAddr(policy['mac-src'])
        if policy['mac-dst'] and (policy['mac-dst'] != '-'):
            matchobj.dl_dst=EthAddr(policy['mac-dst'])
        

        if policy['ip-src'] and (policy['ip-src'] != '-'):
            #print(type(policy['ip-src']))
            matchobj.nw_src=policy['ip-src']

        if policy['ip-dst'] and (policy['ip-dst'] != '-'):

            matchobj.nw_dst=policy['ip-dst']
        
        if policy['ipprotocol'] and (policy['ipprotocol'] != '-'):
            matchobj.nw_proto = int(policy['ipprotocol'])
            
        if policy['port-src'] and (policy['port-src'] != '-'):
            matchobj.tp_src=int(policy['port-src'])
        if policy['port-dst'] and (policy['port-dst'] != '-'):
            matchobj.tp_dst=int(policy['port-dst'])
        
        #All traffic IPV4
        matchobj.dl_type=0x800

        rule.match=matchobj
        
        action=policy['action']

        if action == 'Allow':
            #Allow has higher priority
            rule.priority=10000
            rule.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))

        if action == 'Block':
            rule.priority=1
            pass

        # End Code Here
        print('Added Rule ',policy['rulenum'],': ',policy['comment'])
        
        print(rule)   #Uncomment this to debug your "rule"
        rules.append(rule)
    
    return rules
