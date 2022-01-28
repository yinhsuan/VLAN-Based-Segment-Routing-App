#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.node import Node
from mininet.link import TCLink

# from mininet.term import makeTerm
# from mininet.node import Link, Host
# from functools import partial


# class VLANHost( Host ):
#     "Host connected to VLAN interface"
#     def config( self, vlan=100, **params ):
#         """Configure VLANHost according to (optional) parameters:
#            vlan: VLAN ID for default interface"""

#         r = super( VLANHost, self ).config( **params )

#         intf = self.defaultIntf()
#         # remove IP from default, "physical" interface
#         self.cmd( 'ifconfig %s inet 0' % intf )
#         # create VLAN interface
#         self.cmd( 'vconfig add %s %d' % ( intf, vlan ) )
#         # assign the host's IP to the VLAN interface
#         self.cmd( 'ifconfig %s.%d inet %s' % ( intf, vlan, params['ip'] ) )
#         # update the intf name and host's intf map
#         newName = '%s.%d' % ( intf, vlan )
#         # update the (Mininet) interface to refer to VLAN interface name
#         intf.name = newName
#         # add VLAN interface to host's name to intf map
#         self.nameToIntf[ newName ] = intf

#         return r

class MyTopo( Topo ):
    def __init__( self ):
        Topo.__init__( self )

        # Add hosts
        h1 = self.addHost( 'h1', ip='10.0.2.1/16', mac='ea:e9:78:fb:fd:01' )
        h2 = self.addHost( 'h2', ip='0.0.0.0', mac='ea:e9:78:fb:fd:02' )
        h3 = self.addHost( 'h3', ip='0.0.0.0', mac='ea:e9:78:fb:fd:03' )
        h4 = self.addHost( 'h4', ip='10.0.3.4/16', mac='ea:e9:78:fb:fd:04' )
        h5 = self.addHost( 'h5', ip='10.0.3.5/16', mac='ea:e9:78:fb:fd:05' )

        # Add switches
        s1 = self.addSwitch( 's1' )
        s2 = self.addSwitch( 's2' )
        s3 = self.addSwitch( 's3' )

        # Add links
        self.addLink( s1, s2 )
        self.addLink( s1, s3 )

        self.addLink( s2, h1 )
        self.addLink( s2, h2 )
        self.addLink( s2, h3 )

        self.addLink( s3, h4 )
        self.addLink( s3, h5 )

#topos = { 'mytopo': MyTopo }



def run():
    topo = MyTopo()
    net = Mininet(topo=topo, controller=None, link=TCLink)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    net.start()

    print("[+] Run DHCP server")
    dhcp = net.getNodeByName('h1')
    dhcp.cmdPrint('/usr/sbin/dhcpd 4 -pf /run/dhcp-server-dhcpd.pid -cf ./dhcpd.conf %s' % dhcp.defaultIntf())

    CLI(net)
    print("[-] Killing DHCP server")
    dhcp.cmdPrint("kill -9 `ps aux | grep h1-eth0 | grep dhcpd | awk '{print $2}'`")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()


