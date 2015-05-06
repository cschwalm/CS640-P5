package edu.wisc.cs.sdn.apps.loadbalancer;

import java.util.List;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFOXMField;
import org.openflow.protocol.OFOXMFieldType;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.action.OFActionSetField;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.openflow.protocol.instruction.OFInstructionType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.wisc.cs.sdn.apps.l3routing.L3Routing;
import edu.wisc.cs.sdn.apps.util.ArpServer;
import edu.wisc.cs.sdn.apps.util.SwitchCommands;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.internal.DeviceManagerImpl;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.util.MACAddress;

public class LoadBalancer implements IFloodlightModule, IOFSwitchListener,
		IOFMessageListener
{
	public static final String MODULE_NAME = LoadBalancer.class.getSimpleName();
	
	private static final byte TCP_FLAG_SYN = 0x02;
	
	private static final short IDLE_TIMEOUT = 20;
	
	// Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;
    
    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Switch table in which rules should be installed
    private byte table;
    
    // Set of virtual IPs and the load balancer instances they correspond with
    private Map<Integer,LoadBalancerInstance> instances;

    LoadBalancerInstance nextInstance;
    /**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Initializing %s...", MODULE_NAME));
		
		// Obtain table number from config
		Map<String,String> config = context.getConfigParams(this);
        this.table = Byte.parseByte(config.get("table"));
        
        // Create instances from config
        this.instances = new HashMap<Integer,LoadBalancerInstance>();
        String[] instanceConfigs = config.get("instances").split(";");
        for (String instanceConfig : instanceConfigs)
        {
        	String[] configItems = instanceConfig.split(" ");
        	if (configItems.length != 3)
        	{ 
        		log.error("Ignoring bad instance config: " + instanceConfig);
        		continue;
        	}
        	LoadBalancerInstance instance = new LoadBalancerInstance(
        			configItems[0], configItems[1], configItems[2].split(","));
            this.instances.put(instance.getVirtualIP(), instance);
            log.info("Added load balancer instance: " + instance);
        }
        
		this.floodlightProv = context.getServiceImpl(
				IFloodlightProviderService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        
        /*********************************************************************/
        /* : Initialize other class variables, if necessary              */
        
        /*********************************************************************/
	}

	/**
     * Subscribes to events and performs other startup tasks.
     */
	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Starting %s...", MODULE_NAME));
		this.floodlightProv.addOFSwitchListener(this);
		this.floodlightProv.addOFMessageListener(OFType.PACKET_IN, this);
		
		/*********************************************************************/
		/* : Perform other tasks, if necessary                           */
		
		/*********************************************************************/
	}
	
	/**
     * Event handler called when a switch joins the network.
     * @param DPID for the switch
     */
	@Override
	public void switchAdded(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d added", switchId));
		
		/*********************************************************************/
		/*  Install rules to send:                                      */
		/*       (1) packets from new connections to each virtual load       */
		/*       balancer IP to the controller                               */
		/*       (2) ARP packets to the controller, and                      */
		/*       (3) all other packets to the next rule table in the switch  */
		
		/*********************************************************************/
		//Notify the controller when a client initiates a TCP connection with a virtual IP—we cannot specify TCP flags 
		//in match criteria, so the SDN switch will notify the controller of each TCP packet sent to a virtual IP which
		//did not match a connection-specific rule (described below)
		
		OFMatch newConnection = new OFMatch();
		newConnection.setDataLayerType(OFMatch.IP_PROTO_TCP);
		List<OFAction> actionList = new ArrayList<OFAction>();
		List<OFInstruction> instructionList = new ArrayList<OFInstruction>();
		
		OFActionOutput output = new OFActionOutput();
		output.setPort(OFPort.OFPP_CONTROLLER);
		actionList.add(output);
		
		OFInstructionApplyActions ac = new OFInstructionApplyActions(actionList);
		instructionList.add(ac);
		SwitchCommands.installRule(sw, table, SwitchCommands.DEFAULT_PRIORITY, newConnection, instructionList);
		
		
		
		// (2) ARP packets to the controller
		//Notify the controller when a client issues an ARP request for the MAC address associated with a virtual IP
		//When a rule should send a packet to the controller, the rule should include an OFInstructionApplyActions whose 
		//set of actions consists of a single OFActionOutput with OFPort.OFPP_CONTROLLER as the port number.
		
		
		OFMatch rule = new OFMatch();
		rule.setDataLayerType(OFMatch.ETH_TYPE_ARP);
		
		
		
		actionList = new ArrayList<OFAction>();
		instructionList = new ArrayList<OFInstruction>();
		
		OFInstructionApplyActions actions = new OFInstructionApplyActions(actionList);
		
		
		output = new OFActionOutput();
		output.setPort(OFPort.OFPP_CONTROLLER);
		actionList.add(output);
		
		//OFInstructionApplyActions instruction = new OFInstructionApplyActions(actionList);
		//instruction.setType(OFInstructionType.WRITE_ACTIONS);

		instructionList.add(actions);
		
		SwitchCommands.installRule(sw, table, SwitchCommands.DEFAULT_PRIORITY, rule, instructionList);
				
		// (3) all other packets to the next rule table in the switch
		//  use L3Routing.table from within the LoadBalancer class to specify the next table id for the OFInstructionGotoTable 
		//  action you specify for some of the rules installed by your load balancer application.
		byte nextTable = L3Routing.table;
		
		OFMatch rule2 = new OFMatch();
		
		
		/**
		 * TODO: figure out how to send everything else to the next switch and then send it
		 */
		
		actionList = new ArrayList<OFAction>();
		instructionList = new ArrayList<OFInstruction>();
		
		actions = new OFInstructionApplyActions(actionList);
		output = new OFActionOutput();
		output.setPort(OFPort.OFPP_CONTROLLER);
		actionList.add(output);
		
		instructionList.add(actions);
		
		SwitchCommands.installRule(sw, table, SwitchCommands.DEFAULT_PRIORITY, rule2, instructionList);
	}
	
	/**
	 * Handle incoming packets sent from switches.
	 * @param sw switch on which the packet was received
	 * @param msg message from the switch
	 * @param cntx the Floodlight context in which the message should be handled
	 * @return indication whether another module should also process the packet
	 */
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) 
	{
		// We're only interested in packet-in messages
		if (msg.getType() != OFType.PACKET_IN)
		{ return Command.CONTINUE; }
		OFPacketIn pktIn = (OFPacketIn)msg;
		
		// Handle the packet
		Ethernet ethPkt = new Ethernet();
		ethPkt.deserialize(pktIn.getPacketData(), 0,
				pktIn.getPacketData().length);
		
		ARP reply = new ARP();
		
		/*********************************************************************/
		/* 															for TCP */
		/*       SYNs sent to a virtual IP, select a host and install        */
		/*       connection-specific rules to rewrite IP and MAC addresses;  */
		/*       ignore all other packets                                    */
		
		/*********************************************************************/		
		
		//Construct and send an ARP reply packet when a client requests the MAC address associated with a virtual IP
		if(ethPkt.getEtherType() == Ethernet.TYPE_ARP)
		{
			ARP arp = (ARP)ethPkt.getPayload();
			
			Ethernet eth = new Ethernet();
			eth.setEtherType(Ethernet.TYPE_ARP);
			eth.setPayload(reply);
			// send an arp reply when client requests a MAC address
			SwitchCommands.sendPacket(sw, (short)pktIn.getInPort(), eth);
		}
		
		else if(ethPkt.getEtherType() == Ethernet.TYPE_IPv4)
		{
			IPv4 ipPkt = (IPv4)ethPkt.getPayload();
			if(ipPkt.getProtocol() == IPv4.PROTOCOL_TCP)
			{
				TCP tcp = (TCP)ipPkt.getPayload();
				if(tcp.getFlags() != TCP_FLAG_SYN)
				{
					return Command.CONTINUE;
				}
				// select a host and install rules to rewrite addresses
				//For each new TCP connection, the load balancer selects 
				//one of the specified hosts (usually in round robin order). The
				//load balancer maintains a mapping of active connections—identified 
				//by the client’s IP and TCP port—to the assigned hosts.
				
				/**
				 * TODO: figure out what host we're sending to
				 */
				//instances.get(0).getNextHostIP();
				
				//The connection-specific rules that modify IP and MAC addresses should 
				//include an instruction to match the modified packets against the rules
				//installed by your layer-3 routing application
				
				//When a rule should rewrite the destination IP and MAC addresses of a packet, 
				//the rule should include an OFInstructionApplyActions whose set of actions consists of:
				//	An OFActionSetField with a field type of OFOXMFieldType.ETH_DST and the desired MAC address as the value
				//	An OFActionSetField with a field type of OFOXMFieldType.IPV4_DST and the desired IP address as the value
				//	The actions for rewriting the source IP and MAC addresses of a packet are similar.
				
				
				// rewrite dst ip and mac
				OFInstructionApplyActions actions = new OFInstructionApplyActions();
				OFActionSetField f1 = new OFActionSetField();
				OFOXMField field1 = new OFOXMField(OFOXMFieldType.ETH_DST, ethPkt.getDestinationMAC());
				f1.setField(field1);
				
				OFActionSetField f2 = new OFActionSetField();
				OFOXMField field2 = new OFOXMField(OFOXMFieldType.IPV4_DST, ipPkt.getDestinationAddress());
				f2.setField(field2);
				
				// rewriting source ip and mac
				OFActionSetField f3 = new OFActionSetField();
				OFOXMField field3 = new OFOXMField(OFOXMFieldType.ETH_SRC, ethPkt.getSourceMAC());
				f3.setField(field3);
				
				OFActionSetField f4 = new OFActionSetField();
				OFOXMField field4 = new OFOXMField(OFOXMFieldType.IPV4_SRC, ipPkt.getSourceAddress());
				f4.setField(field4);
				
				ArrayList<OFAction> actionList = new ArrayList<OFAction>();
				actionList.add(f1);
				actionList.add(f2);
				actionList.add(f3);
				actionList.add(f4);
	
				/** 
				 * TODO: actually send the rule
				 */
				
			}
		}
		
		// We don't care about other packets
		return Command.CONTINUE;
	}
	
	/**
	 * Returns the MAC address for a host, given the host's IP address.
	 * @param hostIPAddress the host's IP address
	 * @return the hosts's MAC address, null if unknown
	 */
	private byte[] getHostMACAddress(int hostIPAddress)
	{
		Iterator<? extends IDevice> iterator = this.deviceProv.queryDevices(
				null, null, hostIPAddress, null, null);
		if (!iterator.hasNext())
		{ return null; }
		IDevice device = iterator.next();
		return MACAddress.valueOf(device.getMACAddress()).toBytes();
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId) 
	{ /* Nothing we need to do, since the switch is no longer active */ }

	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId)
	{ /* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when a port on a switch goes up or down, or is
	 * added or removed.
	 * @param DPID for the switch
	 * @param port the port on the switch whose status changed
	 * @param type the type of status change (up, down, add, remove)
	 */
	@Override
	public void switchPortChanged(long switchId, ImmutablePort port,
			PortChangeType type) 
	{ /* Nothing we need to do, since load balancer rules are port-agnostic */}

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId) 
	{ /* Nothing we need to do */ }
	
    /**
     * Tell the module system which services we provide.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() 
	{ return null; }

	/**
     * Tell the module system which services we implement.
     */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> 
			getServiceImpls() 
	{ return null; }

	/**
     * Tell the module system which modules we depend on.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> 
			getModuleDependencies() 
	{
		Collection<Class<? extends IFloodlightService >> floodlightService =
	            new ArrayList<Class<? extends IFloodlightService>>();
        floodlightService.add(IFloodlightProviderService.class);
        floodlightService.add(IDeviceService.class);
        return floodlightService;
	}

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName() 
	{ return MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) 
	{
		return (OFType.PACKET_IN == type 
				&& (name.equals(ArpServer.MODULE_NAME) 
					|| name.equals(DeviceManagerImpl.MODULE_NAME))); 
	}

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) 
	{ return false; }
}
