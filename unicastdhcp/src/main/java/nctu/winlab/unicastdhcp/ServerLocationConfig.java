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

import org.onosproject.core.ApplicationId;
import org.onosproject.net.config.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ServerLocationConfig extends Config<ApplicationId> {

  public static final String SERVERLOCATION = "serverLocation";
  private final Logger log = LoggerFactory.getLogger(getClass());

  @Override
  public boolean isValid() {
    // log.info("Enter isValid!!!");
    return hasOnlyFields(SERVERLOCATION);
  }

  public String serverLocation() {
    // log.info("Enter get serverLocation!!!");
    return get(SERVERLOCATION, null);
  }

  
}
