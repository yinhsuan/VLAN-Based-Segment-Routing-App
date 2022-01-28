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

// import org.onosproject.core.ApplicationId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.config.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.onlab.packet.IpPrefix;

public class VlanConfig extends Config<DeviceId> {

    public static final String SEGMENTID = "SegmentId"; 
    public static final String SUBNET = "Subnet"; 
    private final Logger log = LoggerFactory.getLogger(getClass());

    @Override
    public boolean isValid() { // if json is valid
        // log.info("Enter isValid!!!");
        return hasOnlyFields(SEGMENTID, SUBNET);
    }

    public String SegmentId() {
        // log.info("Enter get SegmentId!!!");
        return get(SEGMENTID, null);
    }

    public String Subnet() {
        // log.info("Enter get Subnet!!!");
        return get(SUBNET, null);
    }

    // public short SegmentId() {
    //     log.info("Enter get SegmentId!!!");
    //     return Short.valueOf(get(SEGMENTID, null));
    // }

    // public IpPrefix Subnet() {
    //     log.info("Enter get Subnet!!!");
    //     return IpPrefix.valueOf(get(SUBNET, null));
    // }
}