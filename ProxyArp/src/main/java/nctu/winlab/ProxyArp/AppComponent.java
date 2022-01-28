/*
 * Copyright 2021-present Open Networking Foundation
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
package nctu.winlab.ProxyArp;

import com.google.common.collect.ImmutableSet;
// import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Dictionary;
import java.util.Properties;

import static org.onlab.util.Tools.get;

// ------------- Added ------------- //
import org.onosproject.store.service.EventuallyConsistentMap;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;

import org.onlab.packet.MacAddress;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IpAddress.Version;
import org.onlab.packet.ARP;
import org.onlab.packet.VlanId;
import org.onlab.util.KryoNamespace;
import org.onlab.graph.Vertex;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.Description;
import org.onosproject.net.DefaultPort;
import org.onosproject.net.topology.Topology;
import org.onosproject.net.topology.TopologyService;
import org.onosproject.net.topology.TopologyGraph;
import org.onosproject.net.topology.TopologyEdge;
import org.onosproject.net.topology.TopologyVertex;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.link.LinkDescription;
import org.onosproject.net.link.LinkService;
import org.onosproject.net.Link;
import org.onosproject.net.Port;
import org.onosproject.net.ElementId;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.host.HostService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Device.Type;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.DefaultOutboundPacket;

import org.onosproject.store.service.EventuallyConsistentMap;
import org.onosproject.store.service.WallClockTimestamp;
import org.onosproject.store.service.MultiValuedTimestamp;
import org.onosproject.store.service.StorageService;
import org.onosproject.store.serializers.KryoNamespaces;

import java.util.HashSet;
import java.util.List;
import java.util.Iterator;
// import javafx.util.Pair;
import java.util.Map;
import java.util.HashMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import java.util.ArrayList;
import java.util.ArrayDeque;
import java.nio.ByteBuffer;
import java.util.stream.Collectors;

// ------------- End of Added ------------- //

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponent {

    private final Logger log = LoggerFactory.getLogger(getClass());

    /** Some configurable property. */
    private EventuallyConsistentMap<IpAddress, MacAddress> ip_mac_table;
	private EventuallyConsistentMap<IpAddress, DeviceId> ip_deviceId_table;
    private EventuallyConsistentMap<Map<IpAddress, DeviceId>, PortNumber> ip_deviceId_port_table;
    private ProxyArpProcessor processor = new ProxyArpProcessor();
    private ApplicationId appId;
    private DeviceId deviceOutput;

    // @Reference(cardinality = ReferenceCardinality.MANDATORY)
    // protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
	protected PacketService packetService;

	@Reference(cardinality = ReferenceCardinality.MANDATORY)
	protected StorageService storageService;

	@Reference(cardinality = ReferenceCardinality.MANDATORY)
	protected FlowRuleService flowRuleService;

	@Reference(cardinality = ReferenceCardinality.MANDATORY)
	protected CoreService coreService;

	@Reference(cardinality = ReferenceCardinality.MANDATORY)
	protected FlowObjectiveService flowObjectiveService;

	@Reference(cardinality = ReferenceCardinality.MANDATORY)
	protected TopologyService topologyService;

	@Reference(cardinality = ReferenceCardinality.MANDATORY)
	protected HostService hostService;

	@Reference(cardinality = ReferenceCardinality.MANDATORY)
	protected LinkService linkService;

	@Reference(cardinality = ReferenceCardinality.MANDATORY)
	protected DeviceService deviceService;

    @Activate
    protected void activate() {
        KryoNamespace.Builder tableSerializer = KryoNamespace.newBuilder()
                .register(KryoNamespaces.API)
                .register(MultiValuedTimestamp.class);
        ip_mac_table = storageService.<IpAddress, MacAddress>eventuallyConsistentMapBuilder()
                .withName("ip2mac-table")
                .withSerializer(tableSerializer)
                .withTimestampProvider((key, metricsData) -> new
                        MultiValuedTimestamp<>(new WallClockTimestamp(), System.nanoTime()))
                .build();
		ip_deviceId_table = storageService.<IpAddress, DeviceId>eventuallyConsistentMapBuilder()
                .withName("ip2id-table")
                .withSerializer(tableSerializer)
                .withTimestampProvider((key, metricsData) -> new
                        MultiValuedTimestamp<>(new WallClockTimestamp(), System.nanoTime()))
                .build();
        ip_deviceId_port_table = storageService.<Map<IpAddress, DeviceId>, PortNumber>eventuallyConsistentMapBuilder()
                .withName("ipdeviceId2port-table")
                .withSerializer(tableSerializer)
                .withTimestampProvider((key, metricsData) -> new
                        MultiValuedTimestamp<>(new WallClockTimestamp(), System.nanoTime()))
                .build();

        // cfgService.registerProperties(getClass());
        appId = coreService.registerApplication("nctu.winlab.ProxyArp");
        packetService.addProcessor(processor, PacketProcessor.director(2));
        requestIntercepts();
        log.info("Started {}", appId.id());
    }

    @Deactivate
    protected void deactivate() {
        // cfgService.unregisterProperties(getClass(), false);        
        packetService.removeProcessor(processor);
        processor = null;
        withdrawIntercepts();
        log.info("Stopped");
    }

    // Request packet in via packet service.
    private void requestIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }
 
    // Cancel request for packet in via packet service.
    private void withdrawIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    private class ProxyArpProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
				return;
			}
			Topology topo = topologyService.currentTopology();
			TopologyGraph graph = topologyService.getGraph(topo);
			InboundPacket pkt = context.inPacket();
			DeviceId device = pkt.receivedFrom().deviceId();
			PortNumber inputPort = pkt.receivedFrom().port();
			Ethernet ethPkt = pkt.parsed();
			ARP arpPacket = (ARP) ethPkt.getPayload();

			MacAddress srcMac = ethPkt.getSourceMAC();
			MacAddress dstMac = ethPkt.getDestinationMAC();
			
			IpAddress srcIp = IpAddress.valueOf(IpAddress.Version.valueOf("INET"), arpPacket.getSenderProtocolAddress());
			IpAddress dstIp = IpAddress.valueOf(IpAddress.Version.valueOf("INET"), arpPacket.getTargetProtocolAddress());

			// Check if source Mac Address is in the IpAddress-macAddress-table
			if(!ip_mac_table.containsKey(srcIp)){
				ip_mac_table.put(srcIp, srcMac);
				// log.info("Add ip_mac_table");
			}

			if(!ip_deviceId_table.containsKey(srcIp)){
				ip_deviceId_table.put(srcIp, device);
			}

            // Check if source Mac Address is in the IpAddress-DeviceID-table
			Map <IpAddress, DeviceId> srcIpDevice = new HashMap<IpAddress, DeviceId>();
            srcIpDevice.put(srcIp, device);
			if (!ip_deviceId_port_table.containsKey(srcIpDevice)){
                // log.info("Add ip_deviceId_port_table");
				ip_deviceId_port_table.put(srcIpDevice, inputPort);
			}

            // Get ARP Request Packet
			if (arpPacket.getOpCode() == ARP.OP_REQUEST) {
				// log.info("Enter ARP REQUEST");
				if (ip_mac_table.containsKey(dstIp)) {					
					MacAddress outputMac = ip_mac_table.get(dstIp);
					Ethernet arpReply = ARP.buildArpReply(dstIp.getIp4Address(), outputMac, ethPkt);

					TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(inputPort).build();
					OutboundPacket packet = new DefaultOutboundPacket(device, treatment, ByteBuffer.wrap(arpReply.serialize()));
					packetService.emit(packet);
					log.info("TABLE HIT. Requested MAC = {}", outputMac);
				}
				else {
					log.info("TABLE MISS. Send request to edge ports.");
					Ethernet arpRequest = ARP.buildArpRequest(srcMac.toBytes(), srcIp.toOctets(), dstIp.toOctets(), VlanId.NO_VID);

					for (TopologyVertex v : graph.getVertexes()){
						List<DefaultPort> devicePorts = new ArrayList<DefaultPort>();
						devicePorts = (List<DefaultPort>)(Object)deviceService.getPorts(v.deviceId());
						List<PortNumber> outputPortList = new ArrayList<PortNumber>();
						for (Iterator<DefaultPort> iter = devicePorts.iterator(); iter.hasNext();){
							DefaultPort p = iter.next();
							List<Link> links = linkService.getDeviceEgressLinks(v.deviceId())
											.stream()
											.filter(c -> c.src().port().equals(p.number()))
											.collect(Collectors.toList());
							if (links.size() == 0) {
								if (p.number().toString() != "LOCAL") {
									if (!(v.deviceId().equals(device) && p.number().equals(inputPort))) {
										TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(p.number()).build();
										OutboundPacket packet = new DefaultOutboundPacket(v.deviceId(), treatment, ByteBuffer.wrap(arpRequest.serialize()));
										packetService.emit(packet);
									}
								}
							}
						}
					}
				}
			}
			// Get ARP Reply Packet
            else if (arpPacket.getOpCode() == ARP.OP_REPLY) {				
				Map <IpAddress, DeviceId> dstIpDevice = new HashMap<IpAddress, DeviceId>();
				DeviceId outputDevice = ip_deviceId_table.get(dstIp);
				// Host host = hostService.getHostsByIp(dstIp).stream()
                // .findFirst()
                // .orElse(null);

                dstIpDevice.put(dstIp, outputDevice);
                PortNumber outputPort = ip_deviceId_port_table.get(dstIpDevice);

				TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(outputPort).build();
				OutboundPacket packet = new DefaultOutboundPacket(outputDevice, treatment, ByteBuffer.wrap(ethPkt.duplicate().serialize()));
				packetService.emit(packet);
				log.info("RECV REPLY. Requested MAC = {}", srcMac);
			}
            else {
                log.info("Not a ARP info!!!");
            }
        }
    }
}
