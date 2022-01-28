/*
* Copyright 2020-present Open Networking Foundation
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
package nctu.winlab.unicastdhcp;

import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_ADDED;
import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_UPDATED;
import static org.onosproject.net.config.basics.SubjectFactories.APP_SUBJECT_FACTORY;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// ------ Added ----- //
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.InboundPacket;

import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.Path;
import org.onosproject.net.PortNumber;

import org.onosproject.net.host.HostService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.topology.TopologyService;

import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficTreatment;

import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;

import org.onlab.packet.Ethernet;
import org.onlab.packet.VlanId;
import org.onlab.packet.MacAddress;
import org.onlab.packet.IPv4;
import org.onlab.packet.TpPort;
import org.onlab.packet.UDP;

import java.util.Set;

// ------ End of Adde ------ //

/** Sample Network Configuration Service Application */
@Component(immediate = true)
public class AppComponent {
	private final Logger log = LoggerFactory.getLogger(getClass());
	private final ServerLocationConfigListener cfgListener = new ServerLocationConfigListener();
	private DHCPServerProcessor processor = new DHCPServerProcessor();
	private final ConfigFactory factory =
	new ConfigFactory<ApplicationId, ServerLocationConfig>(
		APP_SUBJECT_FACTORY, ServerLocationConfig.class, "UnicastDhcpConfig") {
		@Override
		public ServerLocationConfig createConfig() {
		return new ServerLocationConfig();
		}
	};
    
	private ApplicationId appId;
	private String DHCP_Device_ID;
	private String DHCP_Device_PORT;

	@Reference(cardinality = ReferenceCardinality.MANDATORY)
	protected NetworkConfigRegistry cfgService;

	@Reference(cardinality = ReferenceCardinality.MANDATORY)
	protected CoreService coreService;

	@Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

	@Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

	@Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected TopologyService topologyService;

	@Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

	@Activate
	protected void activate() {
		appId = coreService.registerApplication("nctu.winlab.unicastdhcp");
		cfgService.addListener(cfgListener);
		cfgService.registerConfigFactory(factory);
		packetService.addProcessor(processor, PacketProcessor.director(2));
		requestIntercepts();
		log.info("Started!!!");

	}

	@Deactivate
	protected void deactivate() {
		cfgService.removeListener(cfgListener);
		cfgService.unregisterConfigFactory(factory);
		log.info("Stopped!!!");
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

	private void flood(PacketContext context) {
        log.info("Flood Packet !!");
        packetOut(context, PortNumber.FLOOD);
    }

	private void packetOut(PacketContext context, PortNumber portNumber) {
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
    }

    private void HtoSinstallRule(PacketContext context, PortNumber dstPortNumber, MacAddress srcMacAddress) {
        log.info("Install HtoSinstallRule !!");
		Ethernet inPkt = context.inPacket().parsed();
		IPv4 ipv4Packet = (IPv4) inPkt.getPayload();
		byte ipv4Protocol = ipv4Packet.getProtocol();

        // install flow entry
        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();

        context.treatmentBuilder().setOutput(dstPortNumber);
        context.send();

		if (ipv4Protocol == IPv4.PROTOCOL_UDP) {
			selectorBuilder.matchIPProtocol(IPv4.PROTOCOL_UDP)
				.matchEthType(Ethernet.TYPE_IPV4)				
				// .matchUdpSrc(TpPort.tpPort(UDP.DHCP_CLIENT_PORT))
				.matchUdpDst(TpPort.tpPort(UDP.DHCP_SERVER_PORT))
				.matchEthSrc(srcMacAddress);
		}

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(dstPortNumber)
                .build();
        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(selectorBuilder.build())
                .withTreatment(treatment)
                .withPriority(30)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .makeTemporary(30)
                .add();
        flowObjectiveService.forward(context.inPacket().receivedFrom().deviceId(),
                forwardingObjective);

        // packet out
        packetOut(context, dstPortNumber);
    }

	private void StoHinstallRule(PacketContext context, PortNumber dstPortNumber, MacAddress dstMacAddress) {
		log.info("Install HtoSinstallRule !!");
		Ethernet inPkt = context.inPacket().parsed();
		IPv4 ipv4Packet = (IPv4) inPkt.getPayload();
		byte ipv4Protocol = ipv4Packet.getProtocol();

        // install flow entry
        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();

        context.treatmentBuilder().setOutput(dstPortNumber);
        context.send();

		if (ipv4Protocol == IPv4.PROTOCOL_UDP) {
			selectorBuilder.matchIPProtocol(IPv4.PROTOCOL_UDP)
				.matchEthType(Ethernet.TYPE_IPV4)				
				.matchUdpSrc(TpPort.tpPort(UDP.DHCP_CLIENT_PORT))
				// .matchUdpSrc(TpPort.tpPort(UDP.DHCP_SERVER_PORT))
				// .matchUdpDst(TpPort.tpPort(UDP.DHCP_CLIENT_PORT))
				.matchEthDst(dstMacAddress);
		}

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(dstPortNumber)
                .build();
        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(selectorBuilder.build())
                .withTreatment(treatment)
                .withPriority(30)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .makeTemporary(30)
                .add();
        flowObjectiveService.forward(context.inPacket().receivedFrom().deviceId(),
                forwardingObjective);

        // packet out
        packetOut(context, dstPortNumber);
	}

    private Path pickForwardPathIfPossible(Set<Path> paths, PortNumber notToPort) {
        for (Path path : paths) {
            if (!path.src().port().equals(notToPort)) {
                return path;
            }
        }
        return null;
    }

	private class ServerLocationConfigListener implements NetworkConfigListener {
		@Override
		public void event(NetworkConfigEvent event) {
			if ((event.type() == CONFIG_ADDED || event.type() == CONFIG_UPDATED)
				&& event.configClass().equals(ServerLocationConfig.class)) {
				ServerLocationConfig config = cfgService.getConfig(appId, ServerLocationConfig.class);
				if (config != null) {
					log.info("DHCP server is at: {}", config.serverLocation());
					String prefix = "of:";
					String jsonStr = config.serverLocation();
					String noPrefixStr = jsonStr.substring(jsonStr.indexOf(prefix) + prefix.length());
					String[] tokens = noPrefixStr.split("/");
					DHCP_Device_ID = tokens[0];
					DHCP_Device_PORT = tokens[1];
					// log.info("serverDeviceId: {}", DHCP_Device_ID);
					// log.info("serverOutputPort: {}", DHCP_Device_PORT);
				}
			}
		}
	}


	private class DHCPServerProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
			if (context.isHandled()) {
                return;
            }
			InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            if (ethPkt == null) {
                return;
            }
			MacAddress srcMacAddress = ethPkt.getSourceMAC();
            PortNumber inputPort = pkt.receivedFrom().port();

			// On edge switch => installRule
            if (pkt.receivedFrom().deviceId().equals(DeviceId.deviceId(DHCP_Device_ID))) {
                if (!context.inPacket().receivedFrom().port().equals(PortNumber.fromString(DHCP_Device_PORT))) {
					// host to server
                    HtoSinstallRule(context, PortNumber.fromString(DHCP_Device_PORT), srcMacAddress); // outputPort/ srcMacAddress
					// server to host
					StoHinstallRule(context, inputPort, srcMacAddress); // outputPort/ dstMacAddress
                }
                return;
            }
			
			// paths => from this switch to dst edge switch
            Set<Path> paths = topologyService.getPaths(topologyService.currentTopology(), pkt.receivedFrom().deviceId(), DeviceId.deviceId(DHCP_Device_ID));
			if (paths.isEmpty()) {
				// log.info("paths.isEmpty()");
                flood(context);
                return;
            }
			// Pick a path that does not lead back to src switch
            Path path = pickForwardPathIfPossible(paths, inputPort);
			if (path == null) {
                // log.warn("Don't know where to go from here {} for {} -> {}", pkt.receivedFrom(), ethPkt.getSourceMAC(), ethPkt.getDestinationMAC());
                flood(context);
                return;
            }           
            // find path => installRule
			// host to server
            HtoSinstallRule(context, path.src().port(), srcMacAddress); // outputPort/ srcMacAddress
			// server to host 
			StoHinstallRule(context, inputPort, srcMacAddress); // outputPort/ dstMacAddress
        }
    }
}




