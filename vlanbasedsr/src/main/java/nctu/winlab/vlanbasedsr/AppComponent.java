/*
 * Copyright 2022-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nctu.winlab.vlanbasedsr;

// import com.google.common.collect.ImmutableSet;
// import org.onosproject.cfg.ComponentConfigService;
// import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
// import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Dictionary;
import java.util.Properties;

import static org.onlab.util.Tools.get;

// ------ Added ----- //
import com.google.common.collect.ImmutableSet;

import org.onosproject.store.service.EventuallyConsistentMap;
import org.onosproject.store.service.MultiValuedTimestamp;
import org.onosproject.store.service.StorageService;
import org.onosproject.store.service.WallClockTimestamp;

import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_ADDED;
import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_UPDATED;
import static org.onosproject.net.config.basics.SubjectFactories.APP_SUBJECT_FACTORY;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;

import org.onosproject.net.PortNumber;
import org.onosproject.net.Path;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Device;
import org.onosproject.net.Device.Type;
import org.onosproject.net.device.DeviceService;

import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.config.basics.SubjectFactories;

import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.InboundPacket;

import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;

import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;

import org.onosproject.net.topology.TopologyService;

import org.onosproject.net.host.HostService;
import org.onosproject.net.Host;

import org.onlab.packet.Ethernet;
import org.onlab.packet.VlanId;
import org.onlab.packet.MacAddress;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IpAddress.Version;
import org.onlab.packet.IPv4;
import org.onlab.packet.IpPrefix;

import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.HashSet;
import java.util.Iterator;

import org.onlab.util.KryoNamespace;
import org.onosproject.store.serializers.KryoNamespaces;


// ------ End of Added ------ //

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponent {
    private ApplicationId appId;
    // private String DHCP_Device_ID = "0000000000000001";
	// private String DHCP_Device_PORT = "2";

    // private String S1_Device_ID = "0000000000000001";
    // private String S2_Device_ID = "0000000000000002";
    // private String S3_Device_ID = "0000000000000003";

    // private short S1_SEGMENT_ID = 102; // of:0000000000000001
    // private short S2_SEGMENT_ID = 101; // of:0000000000000002
    // private short S3_SEGMENT_ID = 103; // of:0000000000000003
    // private short DEFAULT_SEGMENT_ID = 100;

    // private String IP_SUBNET2 = "10.0.2.0/24";
    // private String IP_SUBNET3 = "10.0.3.0/24";

    // private EventuallyConsistentMap<String, MacAddress> subnetIp_vlan_table;
    // private EventuallyConsistentMap<Map<IpAddress, DeviceId>, PortNumber> deviceId_vlan_port_table;
    private EventuallyConsistentMap<DeviceId, Map<IpPrefix, VlanId>> subnet_segmentId_table;
    private EventuallyConsistentMap<Map<DeviceId, MacAddress>, PortNumber> macTable;
    private EventuallyConsistentMap<MacAddress, IpAddress> ip_mac_Table;

    private final Logger log = LoggerFactory.getLogger(getClass());
    private final VlanConfigListener cfgListener = new VlanConfigListener();
    private VlanBaseDsrProcessor processor = new VlanBaseDsrProcessor();
    private final ConfigFactory factory =
	new ConfigFactory<DeviceId, VlanConfig>(
		SubjectFactories.DEVICE_SUBJECT_FACTORY, VlanConfig.class, "SegmentConfig") {
		@Override
		public VlanConfig createConfig() {
		    return new VlanConfig();
		}
	};

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
	protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected StorageService storageService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
	protected TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Activate
    protected void activate() {
        KryoNamespace.Builder tableSerializer = KryoNamespace.newBuilder()
                .register(KryoNamespaces.API)
                .register(MultiValuedTimestamp.class);
        subnet_segmentId_table = storageService.<DeviceId, Map<IpPrefix, VlanId>>eventuallyConsistentMapBuilder()
                .withName("subnet_segmentId_table")
                .withSerializer(tableSerializer)
                .withTimestampProvider((key, metricsData) -> new
                        MultiValuedTimestamp<>(new WallClockTimestamp(), System.nanoTime()))
                .build();
        macTable = storageService.<Map<DeviceId, MacAddress>, PortNumber>eventuallyConsistentMapBuilder()
                .withName("macAddress-table")
                .withSerializer(tableSerializer)
                .withTimestampProvider((key, metricsData) -> new
                        MultiValuedTimestamp<>(new WallClockTimestamp(), System.nanoTime()))
                .build();
        ip_mac_Table = storageService.<MacAddress, IpAddress>eventuallyConsistentMapBuilder()
                .withName("ip_mac_Table")
                .withSerializer(tableSerializer)
                .withTimestampProvider((key, metricsData) -> new
                        MultiValuedTimestamp<>(new WallClockTimestamp(), System.nanoTime()))
                .build();

        appId = coreService.registerApplication("nctu.winlab.vlanbasedsr");
        cfgService.addListener(cfgListener);
        cfgService.registerConfigFactory(factory);
        // cfgService.registerProperties(getClass());
        packetService.addProcessor(processor, PacketProcessor.director(2));
        requestIntercepts();
        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        cfgService.removeListener(cfgListener);
        cfgService.unregisterConfigFactory(factory);
        // cfgService.unregisterProperties(getClass(), false);
        withdrawIntercepts();
        log.info("Stopped");
    }

    

    // Request packet in via packet service.
    private void requestIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    // Cancel request for packet in via packet service.
    private void withdrawIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }


    private void installRule_ROUTE(DeviceId deviceId, PortNumber portNumber, VlanId segmentId) {
        log.info("Install installRule_ROUTE !!");

        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();
        selectorBuilder.matchEthType(Ethernet.TYPE_IPV4)
                .matchVlanId(segmentId);
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(portNumber)
                .build();
        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(selectorBuilder.build())
                .withTreatment(treatment)
                .withPriority(20)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .makePermanent()
                .add();
        flowObjectiveService.forward(deviceId, forwardingObjective);
    }

    private void installRule_FORWARD(DeviceId deviceId, PortNumber portNumber, MacAddress dstMacAddress) {
        log.info("Install installRule_FORWARD !!");

        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();
        selectorBuilder.matchEthType(Ethernet.TYPE_IPV4)
                .matchEthDst(dstMacAddress);
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(portNumber)
                .build();
        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(selectorBuilder.build())
                .withTreatment(treatment)
                .withPriority(25)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .makePermanent()
                .add();
        flowObjectiveService.forward(deviceId, forwardingObjective);
    }

    private void installRule_PUSH(DeviceId deviceId, PortNumber portNumber, IpPrefix dstIpPrefix, VlanId segmentId) {
        log.info("Install installRule_PUSH !!");

        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();
        selectorBuilder.matchEthType(Ethernet.TYPE_IPV4)
                .matchIPDst(dstIpPrefix);
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(portNumber)
                .pushVlan()
                .setVlanId(segmentId)
                .build();
        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(selectorBuilder.build())
                .withTreatment(treatment)
                .withPriority(15)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .makePermanent()
                .add();
        flowObjectiveService.forward(deviceId, forwardingObjective);
    }

    private void installRule_POP(DeviceId deviceId, PortNumber portNumber, MacAddress dstMacAddress, VlanId segmentId) {
    // private void installRule_POP(DeviceId deviceId, PortNumber portNumber, IpPrefix dstIp, VlanId segmentId) {
        log.info("Install installRule_POP !!");

        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();
        selectorBuilder.matchEthType(Ethernet.TYPE_IPV4)
                .matchVlanId(segmentId)
                .matchEthDst(dstMacAddress);
                // .matchIPDst(dstIp);
                
                
                
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(portNumber)
                .popVlan()
                .build();
        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(selectorBuilder.build())
                .withTreatment(treatment)
                .withPriority(30)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .makePermanent()
                .add();
        flowObjectiveService.forward(deviceId, forwardingObjective);
    }

    private void flood(PacketContext context) {
        // log.info("Flood Packet !!");
        packetOut(context, PortNumber.FLOOD);
    }

    private void packetOut(PacketContext context, PortNumber portNumber) {
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
    }

    private Path pickForwardPathIfPossible(Set<Path> paths) {        
        for (Path path : paths) {
            // log.info("Enter pickForwardPathIfPossible !!");
            // should be true if exists any path
            return path;
        }
        return null;
    }

    // private VlanId ipToVlanId(String ip) {
    //     String subnetIp = ip.substring(0, ip.lastIndexOf('.')); 
    //     if (subnetIp.equals(IP_SUBNET2.substring(0, ip.lastIndexOf('.')))) {
    //         return 	VlanId.vlanId(S2_SEGMENT_ID);
    //     }
    //     else if (subnetIp.equals(IP_SUBNET3.substring(0, ip.lastIndexOf('.')))) {
    //         return 	VlanId.vlanId(S3_SEGMENT_ID);
    //     }
    //     return VlanId.vlanId(DEFAULT_SEGMENT_ID);
    // }

    private class VlanConfigListener implements NetworkConfigListener {
		@Override
		public void event(NetworkConfigEvent event) {
			if ((event.type() == CONFIG_ADDED || event.type() == CONFIG_UPDATED)
				&& event.configClass().equals(VlanConfig.class)) {
                // log.info("DeviceCount: {}", deviceService.getDeviceCount());
                // log.info("event.subject: {}", event.subject());
                
                for (Device device : deviceService.getDevices()) {
                    VlanConfig config = cfgService.getConfig(device.id(), VlanConfig.class);
                    if (config != null) {                        
                        log.info("DeviceId: {}", device.id());
                        log.info("SegmentId: {}", config.SegmentId());
                        log.info("Subnet: {}", config.Subnet());

                        VlanId segmentId = VlanId.vlanId(config.SegmentId());
                        IpPrefix subnet;

                        String jsonStr = config.Subnet();
                        if (jsonStr != null) {
                            String[] tokens = jsonStr.split("/");  
                            log.info("tokens[0]: {}", tokens[0]);
                            log.info("tokens[1]: {}", tokens[1]);
                            subnet = IpPrefix.valueOf(IpAddress.valueOf(tokens[0]), Integer.valueOf(tokens[1]));
                        }
                        else {
                            log.info("jsonStr is null"); // ex: switch 1
                            subnet = IpPrefix.valueOf(IpAddress.valueOf("10.0.0.0"), 0);
                        }
                        
                        // STEP 0: Get Table (subnet_segmentId_table)
                        Map <IpPrefix, VlanId> segmentConfig = new HashMap<IpPrefix, VlanId>();
                        segmentConfig.put(subnet, segmentId);
                        subnet_segmentId_table.put(device.id(), segmentConfig);

                        for (Host host : hostService.getConnectedHosts(device.id())) {
                            Map <DeviceId, MacAddress> dstMacPort = new HashMap<DeviceId, MacAddress>();
                            dstMacPort.put(device.id(), host.mac());
                            log.info("Host MacAddress: {}", host.mac());

                            // STEP 1: On edge switch => InstallRule for POP_VLAN
                            
                            // installRule_POP(device.id(), host.location().port(), IpPrefix.valueOf(ip_mac_Table.get(host.mac()), Integer.valueOf(32)), segmentId);
                            // installRule_POP(device.id(), macTable.get(dstMacPort), IpPrefix.valueOf(ip_mac_Table.get(host.mac()), Integer.valueOf(32)), segmentId);
                            installRule_POP(device.id(), host.location().port(), host.mac(), segmentId);

                            // STEP 2: On Local => InstallRule for Forwarding
                            installRule_FORWARD(device.id(), host.location().port(), host.mac());
                        }
                    }
                }

                Iterable<Device> devicesS = deviceService.getDevices();
                Iterable<Device> devicesD = deviceService.getDevices();      
                for (Device deviceSrc : devicesS) {
                    for (Device deviceDst : devicesD) {
                        log.info("deviceSrc: {}", deviceSrc.id());
                        log.info("deviceDst: {}", deviceDst.id());

                        Iterator<Map.Entry<IpPrefix, VlanId>> it_S = subnet_segmentId_table.get(deviceSrc.id()).entrySet().iterator();
                        Iterator<Map.Entry<IpPrefix, VlanId>> it_D = subnet_segmentId_table.get(deviceDst.id()).entrySet().iterator();
                        if (it_D.hasNext() && it_S.hasNext()) {
                            Map.Entry<IpPrefix, VlanId> element_S = it_S.next();
                            IpPrefix srcSubnet = element_S.getKey();
                            log.info("srcSubnet: {}", srcSubnet);

                            Map.Entry<IpPrefix, VlanId> element_D = it_D.next();
                            IpPrefix dstSubnet = element_D.getKey();
                            log.info("dstSubnet: {}", dstSubnet);
                            VlanId dstSegmentId = element_D.getValue();
                            log.info("dstSegmentId: {}", dstSegmentId);
                            
                            // if (!deviceSrc.equals(deviceDst) && (dstSubnet.prefixLength() != 0)) {
                            if (!deviceSrc.equals(deviceDst)) {
                                    log.info("Enter getPath !!");
                                    Set<Path> paths = topologyService.getPaths(topologyService.currentTopology(), deviceSrc.id(), deviceDst.id());
                                    Path path = pickForwardPathIfPossible(paths);                                    
                                    
                                    // if (srcSubnet.prefixLength() != 0) {
                                        // log.info("Enter srcSubnet prefixLength !!");
                                        log.info("deviceSrc.id(): {}", deviceSrc.id());
                                        log.info("path.src().port(): {}", path.src().port());
                                        log.info("dstSubnet: {}", dstSubnet);
                                        log.info("dstSegmentId: {}", dstSegmentId);
                                        // STEP 4: On first switch => InstallRule for PUSH_VLAN
                                        installRule_PUSH(deviceSrc.id(), path.src().port(), dstSubnet, dstSegmentId);
                                    // }
                                    log.info("Enter final ROUTE !!");
                                    // STEP 3: On middle switch => InstallRule for Segment Routing
                                    installRule_ROUTE(deviceSrc.id(), path.src().port(), dstSegmentId);
                                    
                            }  
                        }                          
                    }
                }
			}
		}
	}

    private class VlanBaseDsrProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
			// log.info("Enter VlanBaseDsrProcessor");
            if (context.isHandled()) {
                return;
            }
			InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            if (ethPkt == null) {
                return;
            }
            DeviceId deviceId = pkt.receivedFrom().deviceId();
            PortNumber inputPort = pkt.receivedFrom().port();
            // VlanId vlanId = VlanId.vlanId(ethPkt.getVlanID());
            IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();

			MacAddress srcMacAddress = ethPkt.getSourceMAC();
            MacAddress dstMacAddress = ethPkt.getDestinationMAC();

            IpAddress dstIp = IpAddress.valueOf(ipv4Packet.getDestinationAddress());
            IpAddress srcIp = IpAddress.valueOf(ipv4Packet.getSourceAddress());


            Map <DeviceId, MacAddress> srcMacPort = new HashMap<DeviceId, MacAddress>();
            srcMacPort.put(deviceId, srcMacAddress);
            Map <DeviceId, MacAddress> dstMacPort = new HashMap<DeviceId, MacAddress>();
            dstMacPort.put(deviceId, dstMacAddress);

            // STEP 0: Get Table (macTable)
            if (!macTable.containsKey(srcMacPort)) {
                macTable.put(srcMacPort, inputPort);   
                ip_mac_Table.put(srcMacAddress, srcIp);         
            }
            if (!macTable.containsKey(dstMacPort)) {
                flood(context);
            }

            // STEP 0: Set Topo
            for (Device deviceSrc : deviceService.getDevices()) {
                for (Device deviceDst : deviceService.getDevices()) {
                    // log.info("deviceSrc: {}", deviceSrc.id());
                    // log.info("deviceDst: {}", deviceDst.id());

                    Set<Path> paths = topologyService.getPaths(topologyService.currentTopology(), deviceSrc.id(), deviceDst.id());
                    if (paths.isEmpty()) {
                        // log.info("topologyService.getPaths flood");
                        flood(context);
                        return;
                    }
                    Path path = pickForwardPathIfPossible(paths);
                    if (path == null) {
                        // log.info("pickForwardPathIfPossible flood");
                        flood(context);
                        return;
                    }          
                }
            }

        }
    }
}
