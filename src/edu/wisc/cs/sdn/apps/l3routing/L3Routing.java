package edu.wisc.cs.sdn.apps.l3routing;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.openflow.protocol.OFMatch;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionType;
import org.python.indexer.ast.NWhile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.wisc.cs.sdn.apps.util.Host;
import edu.wisc.cs.sdn.apps.util.SwitchCommands;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceListener;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.routing.Link;

public class L3Routing implements IFloodlightModule, IOFSwitchListener, 
		ILinkDiscoveryListener, IDeviceListener
{
	public static final String MODULE_NAME = L3Routing.class.getSimpleName();
	
	// Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;

    // Interface to link discovery service
    private ILinkDiscoveryService linkDiscProv;

    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Switch table in which rules should be installed
    public static byte table;
    
    // Map of hosts to devices
    private Map<IDevice,Host> knownHosts;
    
    private void bellmanFord2() {
    	
    	for (Host h : this.getHosts()) {
    		
    		HashMap<Long, Integer> switchToDistance = new HashMap<Long, Integer>();
    		HashMap<Long, Integer> switchToPort = new HashMap<Long, Integer>();

    		//Part 1 of Wikipedia Bellman Ford Algorithm
    		for (IOFSwitch v : this.getSwitches().values()) {
    			
    			/* If Destination Host is Connected to current switch, set weight to 0 */
    			if (v.getId() == h.getSwitch().getId()) {
    				
    				switchToDistance.put(v.getId(), 0);
    				switchToPort.put(v.getId(), h.getPort());
    				
    			/* Otherwise set to to infinity */
    			} else {
    				
    				switchToDistance.put(v.getId(), Integer.MAX_VALUE);
    			}
    			
    			switchToPort.put(v.getId(), null);
    		}	
    			
    		//Part 2 of Wikipedia Bellman Ford Algorithm
    		for (int i = 1; i < (this.getSwitches().size() - 1); i++) {
    			
    			for (Link l : this.getLinks()) {
    				
    				int distanceSrc = switchToDistance.get(l.getSrc());
    				int distanceDesc = switchToDistance.get(l.getDst());
    				
    				if (distanceSrc + 1 < distanceDesc) {
    					
    					switchToDistance.put(l.getDst(), distanceSrc + 1);
    					switchToPort.put(l.getDst(), l.getDstPort());
    				}
    				
    			}
    				
    		}
    		
    		//Add Rules
  
    		
    	}
    }
    
    /**
     * This method runs for each host.
     * It should be called on setup, add, and remove.
     * 
     */
    private void bellmanFord() {
    	
    	for (IOFSwitch s : this.getSwitches().values()) {
    		
    		int[] distance = new int[100];
    		int[] predecessor = new int[100];
    		HashMap<Integer, IOFSwitch> idMap = new HashMap<Integer, IOFSwitch>();
    		
    		/* Maps path counts to hosts */
    		//HashMap<Integer, Host> paths = new HashMap<Integer, Host>();
    		
    		//Step 1
    		int vID = 0;
    		for (IOFSwitch v : this.getSwitches().values()) {
    			
    			idMap.put(new Integer(vID), v);
    			
    			if (v.getId() == s.getId()) {
    				distance[vID] = 0;
    			} else {
    				distance[vID] = Integer.MAX_VALUE;
    			}
    			predecessor[vID] = -1;
    			vID++;
    		}
    		
    		for(int i = 1; i < this.getSwitches().size() - 1; i++)
    		{
    			for(Link l : this.getLinks())
    			{
    				if(distance[(int) l.getSrc()] + 1 < distance[(int) l.getDst()]) {
    					distance[(int) l.getDst()] = distance[(int) l.getSrc()] + 1;
    					predecessor[(int) l.getDst()] = (int) l.getSrc();
    				}
 
    			}
    		}
    		
    		// Code here to add rules
    		// iterate over all the vertices
    		// Determine the attached host IP addresses
    		// Add each host IP to each vertice predecessor
    		for (int i = 0; i < distance.length; i++) {
    			
    			if (predecessor[i] == -1) {
    				continue;
    				
    			}
    			
    			/* Determine List of Connected Hosts For Index */
    			ArrayList<Host> hosts = new ArrayList<Host>();
    			
    			for (Host h : this.getHosts()) {
    				
    				if (h.getSwitch().getId() == idMap.get(i).getId()) {
    					hosts.add(h);
    				}
    			}
    			
    			/* For each host, add a rule to predecessor */
    			for (Host h : hosts) {
    				
    				IOFSwitch predecessorSwitch = idMap.get(predecessor[i]);
    				
    				OFMatch matchCriteria = new OFMatch();
    				matchCriteria.setDataLayerType(OFMatch.ETH_TYPE_IPV4);
    				matchCriteria.setNetworkDestination(h.getIPv4Address());
    				
    				ArrayList<OFInstruction> instructions = new ArrayList<OFInstruction>();
    				ArrayList<OFAction> actions = new ArrayList<OFAction>();
    				
    				OFActionOutput action = new OFActionOutput();
    				
    				
    				/* TODO: Double Check GetTables() is correct */
    				//SwitchCommands.installRule(predecessorSwitch, predecessorSwitch.getTables(), SwitchCommands.DEFAULT_PRIORITY, matchCriteria, instructions);
    			}
    			
    		}
    	}
    }
    
    /**
     * Uses the results of the Bellman-Ford algorithm to determine the next
     * switch to add a 
     * @param src
     * @param desc
     * @param distance
     * @param predecessor
     */
    private void calculateNextSwitch(int src, int desc, int[] distance, int[] predecessor) {
    	
    	
    }
    
	/**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Initializing %s...", MODULE_NAME));
		Map<String,String> config = context.getConfigParams(this);
        this.table = Byte.parseByte(config.get("table"));
        
		this.floodlightProv = context.getServiceImpl(
				IFloodlightProviderService.class);
        this.linkDiscProv = context.getServiceImpl(ILinkDiscoveryService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        
        this.knownHosts = new ConcurrentHashMap<IDevice,Host>();
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
		this.linkDiscProv.addListener(this);
		this.deviceProv.addListener(this);
		
		/*********************************************************************/
		/* TODO: Initialize variables or perform startup tasks, if necessary */
		
		/*********************************************************************/
	}
	
    /**
     * Get a list of all known hosts in the network.
     */
    private Collection<Host> getHosts()
    { return this.knownHosts.values(); }
	
    /**
     * Get a map of all active switches in the network. Switch DPID is used as
     * the key.
     */
	private Map<Long, IOFSwitch> getSwitches()
    { return floodlightProv.getAllSwitchMap(); }
	
    /**
     * Get a list of all active links in the network.
     */
    private Collection<Link> getLinks()
    { return linkDiscProv.getLinks().keySet(); }

    /**
     * Event handler called when a host joins the network.
     * @param device information about the host
     */
	@Override
	public void deviceAdded(IDevice device) 
	{
		Host host = new Host(device, this.floodlightProv);
		// We only care about a new host if we know its IP
		if (host.getIPv4Address() != null)
		{
			log.info(String.format("Host %s added", host.getName()));
			this.knownHosts.put(device, host);
			
			// run bellman-ford to figure out all the shortest paths to a new host
			/*****************************************************************/
			/* TODO: Update routing: add rules to route to new host          */
			
			/*****************************************************************/
		}
	}

	/**
     * Event handler called when a host is no longer attached to a switch.
     * @param device information about the host
     */
	@Override
	public void deviceRemoved(IDevice device) 
	{
		Host host = this.knownHosts.get(device);
		if (null == host)
		{ return; }
		this.knownHosts.remove(host);
		
		log.info(String.format("Host %s is no longer attached to a switch", 
				host.getName()));
		
		// redo bellman-ford here too
		/*********************************************************************/
		/* TODO: Update routing: remove rules to route to host               */
		
		/*********************************************************************/
	}

	/**
     * Event handler called when a host moves within the network.
     * @param device information about the host
     */
	@Override
	public void deviceMoved(IDevice device) 
	{
		Host host = this.knownHosts.get(device);
		if (null == host)
		{
			host = new Host(device, this.floodlightProv);
			this.knownHosts.put(device, host);
		}
		
		if (!host.isAttachedToSwitch())
		{
			this.deviceRemoved(device);
			return;
		}
		log.info(String.format("Host %s moved to s%d:%d", host.getName(),
				host.getSwitch().getId(), host.getPort()));
		
		// re run bellman-ford to get new paths
		/*********************************************************************/
		/* TODO: Update routing: change rules to route to host               */
		
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
		/* TODO: Update routing: change routing rules for all hosts          */
		
		/*********************************************************************/
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d removed", switchId));
		
		/*********************************************************************/
		/* TODO: Update routing: change routing rules for all hosts          */
		
		/*********************************************************************/
	}

	/**
	 * Event handler called when multiple links go up or down.
	 * @param updateList information about the change in each link's state
	 */
	@Override
	public void linkDiscoveryUpdate(List<LDUpdate> updateList) 
	{
		for (LDUpdate update : updateList)
		{
			// If we only know the switch & port for one end of the link, then
			// the link must be from a switch to a host
			if (0 == update.getDst())
			{
				log.info(String.format("Link s%s:%d -> host updated", 
					update.getSrc(), update.getSrcPort()));
			}
			// Otherwise, the link is between two switches
			else
			{
				log.info(String.format("Link s%s:%d -> s%s:%d updated", 
					update.getSrc(), update.getSrcPort(),
					update.getDst(), update.getDstPort()));
			}
		}
		
		/*********************************************************************/
		/* TODO: Update routing: change routing rules for all hosts          */
		
		/*********************************************************************/
	}

	/**
	 * Event handler called when link goes up or down.
	 * @param update information about the change in link state
	 */
	@Override
	public void linkDiscoveryUpdate(LDUpdate update) 
	{ this.linkDiscoveryUpdate(Arrays.asList(update)); }
	
	/**
     * Event handler called when the IP address of a host changes.
     * @param device information about the host
     */
	@Override
	public void deviceIPV4AddrChanged(IDevice device) 
	{ this.deviceAdded(device); }

	/**
     * Event handler called when the VLAN of a host changes.
     * @param device information about the host
     */
	@Override
	public void deviceVlanChanged(IDevice device) 
	{ /* Nothing we need to do, since we're not using VLANs */ }
	
	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId) 
	{ /* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId) 
	{ /* Nothing we need to do */ }
	
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
	{ /* Nothing we need to do, since we'll get a linkDiscoveryUpdate event */ }

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName() 
	{ return this.MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(String type, String name) 
	{ return false; }

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(String type, String name) 
	{ return false; }
	
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
        floodlightService.add(ILinkDiscoveryService.class);
        floodlightService.add(IDeviceService.class);
        return floodlightService;
	}
}
