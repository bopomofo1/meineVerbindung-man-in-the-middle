from mininet.topo import Topo

class Project( Topo ):
    def __init__( self ):
        # Initialize topology
        Topo.__init__( self )
        # Add hosts
        server = self.addHost('server')
        wir = self.addHost('wir')
        client = self.addHost('client')

        # Add switches
        s1 = self.addSwitch('s1')

        # Add links
        self.addLink(server,s1)
        self.addLink(wir,s1)
        self.addLink(client,s1)

topos = { 'project': ( lambda: Project() )} 