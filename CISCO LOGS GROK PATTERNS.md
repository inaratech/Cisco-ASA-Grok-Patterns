# CiscoASA Grok Patterns

The following **_Grok Pattern Definitions_** are used.

```
DATA .*?
QUOTEDSTRING (?>(?<!\\)(?>"(?>\\.|[^\\"]+)+"|""|(?>'(?>\\.|[^\\']+)+')|''|(?>`(?>\\.|[^\\`]+)+`)|``))
QS %{QUOTEDSTRING}
GREEDYDATA .*
CS \b[\w\-]+\b
CISCOTIMESTAMP %{MONTH} +%{MONTHDAY} +%{TIME}
CISCO_DIRECTION Inbound|inbound|Outbound|outbound
CISCO_INTERVAL first hit|%{INT}-second interval
CISCO_XLATE_TYPE static|dynamic
SYSTEMACTION Monitoring|Testing
SYSTEMACTIONSTATUS waiting|normal|Passed|Failed|Undetermined
CISCOTAG [A-Z0-9]+-%{INT}-(?:[A-Z0-9_]+)
SYSLOGHOST %{IPORHOST}
CISCO_ACTION Built|Teardown|Deny|Denied|denied|requested|permitted|denied by ACL|discarded|est-allowed|Dropping|created|deleted
CISCO_REASON Duplicate TCP SYN|Failed to locate egress interface|Invalid transport field|No matching connection|DNS Response|DNS Query|(?:%{WORD}\s*)*
QUOTE \"
CISCOFW------ TAG DEFINITION HERE.
```

**CiscoASA Tag Definitions**

| CISCOFW607001 |
| ------ |
| **Error Message:** |
| %ASA-6-607001: Pre-allocate SIP connection_type secondary channel for interface_name:IP_address/port to interface_name:IP_address from string message |
| **Grok Pattern:** |
| `CISCOFW607001 Pre-allocate %{GREEDYDATA:protocol} secondary channel for %{DATA:src_interface}:%{IP:src_ip}(/%{INT:src_port})? to %{DATA:dst_interface}:%{IP:dst_ip}(/%{INT:dst_port})? from %{DATA:voip_message} message` |

| CiscoASA-303002 |
| ------ |
| **Error Message:** |
| %ASA-6-303002: FTP connection from src_ifc :src_ip /src_port to dst_ifc :dst_ip /dst_port , user username action file filename |
| **Grok Pattern:** |
| `CISCOFW303002 FTP connection from %{GREEDYDATA:src_interface}:%{IP:src_ip}/%{INT:src_port} to %{GREEDYDATA:dst_interface}:%{IP:dst_ip}/%{INT:dst_port}, user(%{DATA:user})? %{WORD:action} file %{GREEDYDATA:filename}` |

| CiscoASA-302021 |
| ------ |
| **Error Message:** |
| %ASA-6-302021: Teardown ICMP connection for faddr \{faddr \| icmp_seq_num } \[(idfw_user )] gaddr \{gaddr \| icmp_type } laddr laddr \[(idfw_user )] type \{type } code \{code } |
| **Grok Pattern:** |
| `CISCOFW302021 %{CISCO_ACTION:action}(?: %{CISCO_DIRECTION:direction})? %{WORD:protocol} connection for faddr %{IP:dst_ip}/%{INT:icmp_seq_num}(?:\(%{DATA:fwuser}\))? gaddr %{IP:src_xlated_ip}/%{INT:icmp_code_xlated} laddr %{IP:src_ip}/%{INT:icmp_code}( \(%{DATA:user}\))?` |

| CiscoASA-302020 |
| ------ |
| **Error Message:** |
| %ASA-6-302020: Built \{in \| out} bound ICMP connection for faddr \{faddr \| icmp_seq_num } \[(idfw_user )] gaddr \{gaddr \| icmp_type } laddr laddr \[(idfw_user )] type \{type } code \{code } |
| **Grok Pattern:** |
| `CISCOFW302020 %{CISCO_ACTION:action}(?: %{CISCO_DIRECTION:direction})? %{WORD:protocol} connection for faddr %{IP:dst_ip}/%{INT:icmp_seq_num}(?:\(%{DATA:fwuser}\))? gaddr %{IP:src_xlated_ip}/%{INT:icmp_code_xlated} laddr %{IP:src_ip}/%{INT:icmp_code}( \(%{DATA:user}\))?` |

| CiscoASA-302014 |
| ------ |
| **Error Message:** |
| %ASA-6-302014: Teardown TCP connection id for interface :real-address /real-port \[(idfw_user )] to interface :real-address /real-port \[(idfw_user )] duration hh:mm:ss bytes bytes \[reason \[from teardown-initiator]] \[(user )] |
| **Grok Pattern:** |
| `CISCOFW302014 %{CISCO_ACTION:action}(?: %{CISCO_DIRECTION:direction})? %{WORD:protocol} connection %{INT:connection_id} for %{DATA:dst_zone}:%{IP:dst_ip}/%{INT:dst_port}( (%{IP:dst_mapped_ip}/%{INT:dst_mapped_port}))?((%{DATA:dst_fwuser}))? to %{DATA:src_zone}:%{IP:src_ip}/%{INT:src_port}( (%{IP:src_mapped_ip}/%{INT:src_mapped_port}))?((%{DATA:src_fwuser}))?( duration %{TIME:duration} bytes %{INT:bytes})?(?: %{CISCO_REASON:reason})?( (%{DATA:user}))?` |

| CiscoASA-302013 |
| ------ |
| **Error Message:** |
| %ASA-6-302013: Built \{inbound\|outbound} TCP connection_id for interface :real-address /real-port (mapped-address/mapped-port ) \[(idfw_user )] to interface :real-address /real-port (mapped-address/mapped-port ) \[(idfw_user )] \[(user )] |
| **Grok Pattern:** |
| `CISCOFW302013 %{CISCO_ACTION:action}(?: %{CISCO_DIRECTION:direction})? %{WORD:protocol} connection %{INT:connection_id} for %{DATA:dst_zone}:%{IP:dst_ip}/%{INT:dst_port} ((%{DATA:dst_fwuser}))? to %{DATA:src_zone}:%{IP:src_ip}/%{INT:src_port} ((%{DATA:src_fwuser}))?` |

| CiscoASA-110003 |
| ------ |
| **Error Message:** |
| %ASA-6-110003: Routing failed to locate next-hop for protocol from src interface :src IP/src port to dest interface :dest IP/dest port |
| **Grok Pattern:** |
| `CISCOFW110003 Routing failed to locate next hop for %{WORD:protocol} from %{GREEDYDATA:src_interface}:%{IP:src_ip}/%{INT:src_port} to %{GREEDYDATA:dst_interface}:%{IP:dst_ip}/%{INT:dst_port}` |

| CiscoASA-110002 |
| ------ |
| **Error Message:** |
| %ASA-6-110002: Failed to locate egress interface for protocol from src interface :src IP/src port to dest IP/dest port |
| **Grok Pattern:** |
| `CISCOFW110002 %{CISCO_REASON:reason} for %{WORD:protocol} from %{GREEDYDATA:src_interface}:%{IP:src_ip}/%{INT:src_port} to %{IP:dst_ip}/%{INT:dst_port}` |

| CiscoASA-106100 |
| ------ |
| **Error Message:** |
| %ASA-6-106100: access-list acl_ID \{permitted \| denied \| est-allowed} protocol interface_name /source_address (source_port ) (idfw_user , sg_info ) interface_name /dest_address (dest_port ) (idfw_user , sg_info ) hit-cnt number (\{first hit \| number -second interval}) hash codes |
| **Grok Pattern:** |
| `CISCOFW106100 access-list %{DATA:policy_id} %{CISCO_ACTION:action} %{WORD:protocol} %{DATA:src_interface}/%{IP:src_ip}\(%{INT:src_port}\) -> %{DATA:dst_interface}/%{IP:dst_ip}\(%{INT:dst_port}\) hit-cnt %{INT:hit_count} %{CISCO_INTERVAL:interval} \[%{DATA:hashcode1}, %{DATA:hashcode2}\]` |

| CiscoASA-106012 |
| ------ |
| **Error Message:** |
| %ASA-6-106012: Deny IP from IP_address to IP_address , IP options hex. |
| **Grok Pattern:** |
| `CISCOFW106012 %{CISCO_ACTION:action} IP from %{IP:src_IP} to %{IP:dst_IP}, IP options: "%{GREEDYDATA:ip_options}"` |

| CiscoASA-746015 |
| ------ |
| **Error Message:** |
|  %ASA-5-746015: user-identity: \[FQDN] fqdn resolved IP address . |
| **Grok Pattern:** |
| `CISCOFW746015 user-identity: %{DATA:fqdn} %{DATA:url} resolved %{IP:src_IP}` |

| CiscoASA-746014 |
| ------ |
| **Error Message:** |
| %ASA-5-746014: user-identity: \[FQDN] fqdn address IP Address obsolete. |
| **Grok Pattern:** |
| `CISCOFW746014 user-identity: %{DATA:fqdn} %{DATA:url} address %{IP:src_IP} obsolete` |

| CiscoASA-500003 |
| ------ |
| **Error Message:** |
| %ASA-5-500003: Bad TCP hdr length (hdrlen=bytes , pktlen=bytes ) from source_address /source_port to dest_address /dest_port , flags: tcp_flags , on interface interface_name |
| **Grok Pattern:** |
| `CISCOFW500003 %{GREEDYDATA:msg_1} from %{IP:src_IP}/%{INT:src_port} to %{IP:dst_IP}/%{INT:dst_port}, flags: %{WORD:flag} , on interface %{GREEDYDATA:interface}` |

| CiscoASA-111010 |
| ------ |
| **Error Message:** |
| %ASA-5-111010: User username , running application-name from IP ip addr , executed cmd |
| **Grok Pattern:** |
| `CISCOFW111010 User '%{DATA:user}', running '%{DATA:data}' from IP %{IP:src_IP}, executed '%{DATA:msg}(host %{IP:host_ip})?'` |

| CiscoASA-111008 |
| ------ |
| **Error Message:** |
| %ASA-5-111008: User user executed the command string |
| **Grok Pattern:** |
| `CISCOFW111008 User '%{DATA:user}' executed the '%{DATA:command}' command\.` |

| CiscoASA-507003 |
| ------ |
| **Error Message:** |
| %ASA-3-507003: The flow of type protocol from the originating interface: src_ip /src_port to dest_if :dest_ip /dest_port terminated by inspection engine, reason-4 |
| **Grok Pattern:** |
| `CISCOFW507003 %{WORD:protocol} flow from %{DATA:src_interface}:%{IPORHOST:src_ip}/%{INT:src_port} to %{DATA:dst_interface}:%{IPORHOST:dst_ip}/%{INT:dst_port} %{CISCO_ACTION:action} by inspection engine, reason - %{DATA:reason}?\.` |

| CiscoASA-500004 |
| ------ |
| **Error Message:** |
| %ASA-4-500004: Invalid transport field for protocol=protocol , from source_address /source_port to dest_address /dest_port |
| **Grok Pattern:** |
| `CISCOFW500004 %{CISCO_REASON:reason} for protocol=%{WORD:protocol}, from %{IP:src_ip}/%{INT:src_port} to %{IP:dst_ip}/%{INT:dst_port}` |

| CiscoASA-419002 |
| ------ |
| **Error Message:** |
| %ASA-4-419002: Received duplicate TCP SYN from in_interface :src_address /src_port to out_interface :dest_address /dest_port with different initial sequence number. |
| **Grok Pattern:** |
| `CISCOFW419002 %{CISCO_REASON:reason} from %{DATA:src_interface}:%{IP:src_ip}/%{INT:src_port} to %{DATA:dst_interface}:%{IP:dst_ip}/%{INT:dst_port} with different initial sequence number` |

| CiscoASA-410001 |
| ------ |
| **Error Message:** |
| %ASA-4-410001: UDP DNS request from source_interface :source_address /source_port to dest_interface :dest_address /dest_port ; (label length \| domain-name length) 52 bytes exceeds remaining packet length of 44 bytes. |
| **Grok Pattern:** |
| `CISCOFW410001 Dropped UDP DNS request from %{GREEDYDATA:src_interface}:%{IP:src_ip}/%{INT:src_port} to %{GREEDYDATA:dst_interface}:%{IP:dst_ip}/%{INT:dst_port}; %{DATA:field_type} length %{INT:field_length} bytes exceeds %{DATA:limit_type} of %{INT:packet_length} bytes` |

| CiscoASA-313009 |
| ------ |
| **Error Message:** |
| %ASA-4-313009: Denied invalid ICMP code icmp-code , for src-ifc :src-address /src-port (mapped-src-address/mapped-src-port) to dest-ifc :dest-address /dest-port (mapped-dest-address/mapped-dest-port) \[user ], ICMP id icmp-id , ICMP type icmp-type |
| **Grok Pattern:** |
| `CISCOFW313009 Denied invalid ICMP code %{INT:icmp_code}, for %{GREEDYDATA:src_interface}:%{IP:src_ip}/%{INT:src_port} \(%{IP:src_mapped_ip}/%{INT:src_mapped_port}\) to %{GREEDYDATA:dst_interface}:%{IP:dst_ip}/%{INT:dst_port} \(%{IP:dst_mapped_ip}/%{INT:dst_mapped_port}\), ICMP id %{INT:icmp_id}, ICMP type %{INT:icmp_type}` |

| CiscoASA-313005 |
| ------ |
| **Error Message:** |
|  %ASA-4-313005: No matching connection for ICMP error message: icmp_msg_info on interface_name interface. Original IP payload: embedded_frame_info icmp_msg_info = icmp src src_interface_name :src_address \[(\[idfw_user \| FQDN_string ], sg_info )] dst dest_interface_name :dest_address \[(\[idfw_user \| FQDN_string ], sg_info )] (type icmp_type, code icmp_code ) embedded_frame_info = prot src source_address /source_port \[(\[idfw_user \| FQDN_string ], sg_info )] dst dest_address /dest_port \[(idfw_user \|FQDN_string ), sg_info ] |
| **Grok Pattern:** |
| `CISCOFW313005 %{CISCO_REASON:reason} for %{WORD:protocol} error message: %{WORD:err_protocol} src %{DATA:err_src_interface}:%{IP:err_src_ip}(\(%{DATA:err_src_fwuser}\))? dst %{DATA:err_dst_interface}:%{IP:err_dst_ip}(\(%{DATA:err_dst_fwuser}\))? \(type %{INT:err_icmp_type}, code %{INT:err_icmp_code}\) on %{DATA:interface} interface\.  Original IP payload: %{WORD:protocol} src %{IP:orig_src_ip}(/%{INT:orig_src_port})?(\(%{DATA:orig_src_fwuser}\))? dst %{IP:orig_dst_ip}(/%{INT:orig_dst_port})?(\(%{DATA:orig_dst_fwuser}\))?(type %{INT:err_icmp_type}, code %{INT:err_icmp_code})?` |

| CiscoASA-313004 |
| ------ |
| **Error Message:** |
| %ASA-4-313004:Denied ICMP type=icmp_type , from source_address on interface interface_name to dest_address :no matching session |
| **Grok Pattern:** |
| `CISCOFW313004 %{CISCO_ACTION:action} %{WORD:protocol} type=%{INT:icmp_type}, (code=%{INT:icmp_code})?(?:%{SPACE})?from (laddr)?(?:%{SPACE})?%{IP:src_ip} on interface %{WORD:interface}( to %{IP:dst_ip})?:?( %{CISCOACTIONDESCRIPTION:description})?` |

| CiscoASA-209005 |
| ------ |
| **Error Message:** |
| %ASA-4-209005: Discard IP fragment set with more than number elements: src = Too many elements are in a fragment set. |
| **Grok Pattern:** |
| `CISCOFW209005 Discard IP fragment set with more than %{INT:elements} elements:  src = %{IP:src_IP}, dest = %{IP:dst_IP}, proto = %{DATA:protocol}, id = %{INT:id}` |

| CiscoASA-106023 |
| ------ |
| **Error Message:** |
| %ASA-4-106023: Deny protocol src \[interface_name :source_address /source_port ] \[(\[idfw_user \|FQDN_string ], sg_info )] dst interface_name :dest_address /dest_port \[(\[idfw_user \|FQDN_string ], sg_info )] \[type \{string }, code \{code }] by access_group acl_ID \[0x8ed66b60, 0xf8852875] |
| **Grok Pattern:** |
| `CISCOFW106023 %{CISCO_ACTION:action}( protocol)? %{WORD:protocol} src %{DATA:src_interface}:%{DATA:src_ip}(/%{INT:src_port})?(\(%{DATA:src_fwuser}\))? dst %{DATA:dst_interface}:%{DATA:dst_ip}(/%{INT:dst_port})?(\(%{DATA:dst_fwuser}\))?( \(type %{INT:icmp_type}, code %{INT:icmp_code}\))? by access-group "?%{DATA:policy_id}"? \[%{DATA:hashcode1}, %{DATA:hashcode2}\]` |

| CiscoASA-106020 |
| ------ |
| **Error Message:** |
| %ASA-2-106020: Deny IP teardrop fragment (size = number, offset = number) from IP_address to IP_address |
| **Grok Pattern:** |
| `CISCOFW106020 %{CISCO_ACTION:action} %{WORD:protocol} %{DATA:cisco_msg}\(size = %{INT:size}, offset = %{INT:offset}\) from %{IP:src_ip} to %{IP:dst_ip}` |

| CiscoASA-106017 |
| ------ |
| **Error Message:** |
| %ASA-2-106017: Deny IP due to Land Attack from IP_address to IP_address |
| **Grok Pattern:** |
| `CISCOFW106017 %{CISCO_ACTION:action} from %{IP:src_ip} to %{IP:dst_IP}` |

| CiscoASA-106021 |
| ------ |
| **Error Message:** |
| %ASA-1-106021: Deny protocol reverse path check from source_address to dest_address on interface interface_name |
| **Grok Pattern:** |
| `CISCOFW106021 %{CISCO_ACTION:action} %{WORD:protocol} %{CISCOACTIONDESCRIPTION:description} from %{IP:src_ip} to %{IP:dst_ip} on interface %{GREEDYDATA:interface}` |

| CiscoASA-717055 |
| ------ |
| **Error Message:** |
| %ASA-1-717055: The type certificate in the trustpoint tp name has expired. Expiration date and time Subject Name subject name Issuer Name issuer name Serial Number serial number |
| **Grok Pattern:** |
| `CISCOFW717055 The <CA> certificate in the trustpoint <%{DATA:certificate}> has expired. Expiration <%{GREEDYDATA:time_data}> Subject Name <%{GREEDYDATA:subject_name} Issuer Name <%{GREEDYDATA:issuer_name}> Serial Number <%{DATA:serial_number}>` |

| CiscoASA-505015 |
| ------ |
| **Error Message:** |
| %ASA-1-505015: Module module_id , application up application , version version |
| %ASA-1-505015: Module prod_id in slot slot_num , application up application , version version |
| **Grok Pattern:** |
| `CISCOFW505015 Module %{DATA:module_id} in slot %{INT:slot_no}, %{GREEDYDATA:message} ""%{DATA:application}"", %{WORD:version} ""%{DATA:version_value}"" %{GREEDYDATA:msg}` |

| CiscoASA-113015 |
| ------ |
| **Error Message:** |
| %ASA-6-113015: AAA user authentication Rejected: reason = reason : local database: user = user: user IP = xxx.xxx.xxx.xxx |
| **Grok Pattern:** |
| `CISCOFW113015 %{GREEDYDATA:msg} : reason = %{GREEDYDATA:reason} : %{GREEDYDATA:reason_msg} : user = %{DATA:user} user IP = %{IP:user_IP}` |

| CiscoASA-113005 |
| ------ |
| **Error Message:** |
| %ASA-6-113005: AAA user authentication Rejected: reason = AAA failure: server = ip_addr : user = *****: user IP = ip_addr |
| **Grok Pattern:** |
| `CISCOFW113005 %{GREEDYDATA:msg} : reason = %{GREEDYDATA:reason} : server = %{IP:server_ip} : user = %{DATA:user} user IP = %{IP:user_IP}` |

| CiscoASA-722051 |
| ------ |
| **Error Message:** |
|  %ASA-6-722051: Group group-policy User username IP public-ip IPv4 Address assigned-ip IPv6 Address assigned-ip assigned to session |
| **Grok Pattern:** |
| `CISCOFW722051 Group <%{DATA:group}> User <%{DATA:user}> IP <%{IP:src_IP}> IPv4 Address <%{IP:IPv4_Address}> IPv6 address <%{IP:IPv6_Address}> %{GREEDYDATA:end_msg}` |

| CiscoASA-113019 |
| ------ |
| **Error Message:** |
| %ASA-4-113019: Group = group , Username = username , IP = peer_address , Session disconnected. Session Type: type , Duration: duration , Bytes xmt: count , Bytes rcv: count , Reason: reason |
| **Grok Pattern:** |
| `CISCOFW113019 Group = %{DATA:group}, Username = %{DATA:username}, IP = %{IP:src_ip}, Session disconnected. Session Type: %{DATA:session_type}, Duration: %{DATA:duration}, Bytes xmt: %{INT:bytes_xmt}, Bytes rcv: %{INT:bytes_rcv}, Reason: %{GREEDYDATA:reason}` |

| CiscoASA-106016 |
| ------ |
| **Error Message:** |
| %ASA-2-106016: Deny IP spoof from (IP_address ) to IP_address on interface interface_name. |
| **Grok Pattern:** |
| `CISCOFW106016 %{WORD:Action} %{GREEDYDATA:initial_msg} \(%{IP:src_ip}\) to %{IP:dst_ip} %{GREEDYDATA:end_msg}` |

| CiscoASA-505013 |
| ------ |
| **Error Message:** |
| %ASA-5-505013: Module module_id application changed from: application version version to: newapplication version newversion . |
| %ASA-5-505013: Module prod_id in slot slot_nunm application changed from: application version version to: newapplication version newversion . |
| **Grok Pattern:** |
| `CISCOFW505013 Module %{DATA:module_id} in slot %{INT:slot_no}, %{GREEDYDATA:message} ""%{DATA:application}"", %{WORD:version} ""%{DATA:version_value}"" %{GREEDYDATA:msg}` |

| CiscoASA-722028 |
| ------ |
| **Error Message:** |
| %ASA-5-722028: Group group User user-name IP IP_address Stale SVC connection closed. |
| **Grok Pattern:** |
| `CISCOFW722028 Group <%{DATA:group}> User <%{DATA:user}> IP <%{IP:src_ip}> %{GREEDYDATA:msg_end}` |

| CiscoASA-722037 |
| ------ |
| **Error Message:** |
| %ASA-5-722037: Group group User user-name IP IP_address SVC closing connection: reason . |
| **Grok Pattern:** |
| `CISCOFW722037 Group <%{DATA:group}> User <%{DATA:user}> IP <%{IP:src_ip}> SVC closing connection: %{GREEDYDATA:reason}` |

| CiscoASA-722023 |
| ------ |
| **Error Message:** |
| %ASA-6-722023: Group group User user-name IP IP_address SVC connection terminated \{with\|without} compression |
| **Grok Pattern:** |
| `CISCOFW722023 Group <%{DATA:group}> User <%{DATA:user}> IP <%{IP:src_ip}> %{WORD:protocol} %{GREEDYDATA:msg}` |

| CiscoASA-722022 |
| ------ |
| **Error Message:** |
| %ASA-6-722022: Group group-name User user-name IP addr (TCP \| UDP) connection established (with \| without) compression |
| **Grok Pattern:** |
| `CISCOFW722022 Group <%{DATA:group}> User <%{DATA:user}> IP <%{IP:src_ip}> %{WORD:protocol} %{GREEDYDATA:message}` |

| CiscoASA-722013 |
| ------ |
| **Error Message:** |
| %ASA-6-722013: Group group User user-name IP IP_address SVC Message: type-num /INFO: message |
| **Grok Pattern:** |
| `CISCOFW722013 Group <%{DATA:group}> User <%{DATA:user}> IP <%{IP:src_ip}> SVC Message: %{INT:msg_num}/%{WORD:msg_word}: %{GREEDYDATA:msg_end}` |

| CiscoASA-722010 |
| ------ |
| **Error Message:** |
| %ASA-5-722010: Group group User user-name IP IP_address SVC Message: type-num /NOTICE: message |
| **Grok Pattern:** |
| `CISCOFW722010 Group <%{DATA:group}> User <%{DATA:user}> IP <%{IP:src_iP}> SVC Message: %{INT:error}/ERROR: %{GREEDYDATA:msg}` |

| CiscoASA-722036 |
| ------ |
| **Error Message:** |
| %ASA-3-722036: Group group User user-name IP IP_address Transmitting large packet length (threshold num ). |
| **Grok Pattern:** |
| `CISCOFW722036 Group <%{DATA:group}> User <%{DATA:user}> IP <%{IP:src_IP}> Transmitting large packet %{INT:packet_length} %{GREEDYDATA:[threshold]}` |

| CiscoASA-722035 |
| ------ |
| **Error Message:** |
| %ASA-3-722035: Group group User user-name IP IP_address Received large packet length (threshold num ). |
| **Grok Pattern:** |
| `CISCOFW722035 Group <%{DATA:group}> User <%{DATA:user}> IP <%{IP:src_ip}> Received large packet %{INT:packet_length} %{GREEDYDATA:[threshold]}.` |

| CiscoASA-722055 |
| ------ |
| **Error Message:** |
| %ASA-6-722055: Group group-policy User username IP public-ip Client Type: user-agent |
| **Grok Pattern:** |
| `CISCOFW722055 Group <%{DATA:group}> User <%{DATA:user}> IP <%{IP:src_ip}> Client Type: %{GREEDYDATA:user_agent}` |

| CiscoASA-722053 |
| ------ |
| **Error Message:** |
| %ASA-6-722053: Group g User u IP ip Unknown client user-agent connection. |
| **Grok Pattern:** |
| `CISCOFW722053 Group <%{DATA:group}> User <%{DATA:user}> IP <%{IP:src_ip}> Unknown client %{GREEDYDATA:user_agent} connection` |

| CiscoASA-722041 |
| ------ |
| **Error Message:** |
| %ASA-4-722041: TunnelGroup tunnel_group GroupPolicy group_policy User username IP peer_address No IPv6 address available for SVC connection. |
| **Grok Pattern:** |
| `CISCOFW722041 TunnelGroup <%{DATA:tunnel_group}> GroupPolicy <%{DATA:group_policy}> User <%{DATA:user}> IP <%{IP:src_ip}> %{GREEDYDATA:message}` |

| CiscoASA-722034 |
| ------ |
| **Error Message:** |
| %ASA-5-722034: Group group User user-name IP IP_address New SVC connection, no existing connection. |
| **Grok Pattern:** |
| `CISCOFW722034 Group <%{DATA:group}> User <%{DATA:user}> IP <%{IP:src_ip}> %{GREEDYDATA:msg_end}` |

| CiscoASA-722033 |
| ------ |
| **Error Message:** |
| %ASA-5-722033: Group group User user-name IP IP_address First SVC connection established for SVC session. |
| **Grok Pattern:** |
| `CISCOFW722033 Group <%{DATA:group}> User <%{DATA:user}> IP <%{IP:src_ip}> %{GREEDYDATA:msg_end}` |

| CiscoASA-722032 |
| ------ |
| **Error Message:** |
| %ASA-5-722032: Group group User user-name IP IP_address New SVC connection replacing old connection. |
| **Grok Pattern:** |
| `CISCOFW722032 Group <%{DATA:group}> User <%{DATA:user}> IP <%{IP:src_ip}> %{GREEDYDATA:msg_end}` |

| CiscoASA-722028 |
| ------ |
| **Error Message:** |
| %ASA-5-722028: Group group User user-name IP IP_address Stale SVC connection closed. |
| **Grok Pattern:** |
| `CISCOFW722028 Group <%{DATA:group}> User <%{DATA:user}> IP <%{IP:src_ip}> %{GREEDYDATA:msg_end}` |

| CiscoASA-722020 |
| ------ |
| **Error Message:** |
| %ASA-3-722020: TunnelGroup tunnel_group GroupPolicy group_policy User user-name IP IP_address No address available for SVC connection |
| **Grok Pattern:** |
| `CISCOFW722020 TunnelGroup %{DATA:tunnel_group} GroupPolicy %{DATA:group_policy} User %{DATA:user} IP <%{IP:src_ip}> %{GREEDYDATA:message}` |

| CiscoASA-722012 |
| ------ |
| **Error Message:** |
|  %ASA-5-722012: Group group User user-name IP IP_address SVC Message: type-num /INFO: message |
| **Grok Pattern:** |
| `CISCOFW722012 Group <%{DATA:group}> User <%{DATA:user}> IP <%{IP:src_iP}> SVC Message: %{INT:msg_num}/%{WORD:msg_word}: %{GREEDYDATA:msg_end}` |

| CiscoASA-722003 |
| ------ |
| **Error Message:** |
| %ASA-4-722003: IP IP_address Error authenticating SVC connect request. |
| **Grok Pattern:** |
| `CISCOFW722003 IP <%{IP:src_ip}> %{GREEDYDATA:message}` |

| CiscoASA-722001 |
| ------ |
| **Error Message:** |
| %ASA-4-722001: IP IP_address Error parsing SVC connect request. |
| **Grok Pattern:** |
| `CISCOFW722001 IP <%{IP:src_ip}> %{GREEDYDATA:message}` |

| CiscoASA-722022 |
| ------ |
| **Error Message:** |
| %ASA-6-722022: Group group-name User user-name IP addr (TCP \| UDP) connection established (with \| without) compression |
| **Grok Pattern:** |
| `CISCOFW722022 Group <%{DATA:group}> User <%{DATA:user}> IP <%{IP:src_ip}> %{WORD:protocol} %{GREEDYDATA:message}` |

| CiscoASA-717009 |
| ------ |
| **Error Message:** |
| %ASA-3-717009: Certificate validation failed. Reason: reason_string . |
| **Grok Pattern:** |
| `CISCO3717009 %{CISCOERRORMESSAGE:error_message}: %{DATA:certificate_serial_number}, subject name: cn=%{DATA:common_name}, issuer name: %{DISTINGUISHEDNAME:distinguished_name} .` |

| CiscoASA-313001 |
| ------ |
| **Error Message:** |
| %ASA-3-313001: Denied ICMP type=number , code=code from IP_address on interface interface_name |
| **Grok Pattern:** |
| `CISCOFW3313001 %{CISCO_ACTION:action} %{WORD:protocol} type=%{INT:icmp_type}, (code=%{INT:icmp_code})?(?:%{SPACE})?from (laddr)?(?:%{SPACE})?%{IP:src_ip} on interface %{WORD:interface}( to %{IP:dst_ip})?:?( %{CISCOACTIONDESCRIPTION:description})?` |

| CiscoASA-106101 |
| ------ |
| **Error Message:** |
| %ASA-1-106101 Number of cached deny-flows for ACL log has reached limit (number ). |
| **Grok Pattern:** |
| `CISCOFW106101 %{CISCOALERTMESSAGE:alert_message} \(%{INT:cache_limit}\)` |

| CiscoASA-305006 |
| ------ |
| **Error Message:** |
| %ASA-3-305006: {outbound static\|identity\|portmap\|regular) translation creation failed for protocol src interface_name:source_address/source_port \[(idfw_user )] dst interface_name:dest_address/dest_port \[(idfw_user )] |
| **Grok Pattern:** |
| `CISCOFW305006 %{CISCOACTIONDESCRIPTION:description} %{WORD:protocol} src %{DATA:src_interface}:%{IPORHOST:src_ip}(/%{INT:src_port})? dst %{DATA:dst_interface}:%{IPORHOST:dst_ip}(/%{INT:dst_port})?(?: \(type %{INT:icmp_type}, code %{INT:icmp_code}\))?` |

| CiscoASA-105004 |
| ------ |
| **Error Message:** |
| %ASA-1-105004: (Primary) Monitoring on interface interface_name normal |
| **Grok Pattern:** |
| `CISCOFW105004 \((?:Primary\|Secondary\|Primary_group_2\|Secondary_group_2)\) Monitoring on [Ii]nterface %{GREEDYDATA:interface_name} %{SYSTEMACTIONSTATUS:system_action_status}` |

| CiscoASA-105003 |
| ------ |
| **Error Message:** |
| %ASA-1-105003: (Primary) Monitoring on interface interface_name waiting |
| **Grok Pattern:** |
| `CISCOFW105003 \((?:Primary\|Secondary\|Primary_group_2\|Secondary_group_2)\) %{SYSTEMACTION:system_action} on [Ii]nterface %{GREEDYDATA:interface_name} %{SYSTEMACTIONSTATUS:system_action_status}` |

| CiscoASA-710001 |
| ------ |
| **Error Message:** |
| %ASA-7-710001: TCP access requested from source_address /source_port to interface_name :dest_address /service |
| **Grok Pattern:** |
| `CISCOFW710001 %{WORD:protocol} (?:request\|access) %{CISCO_ACTION:action} from %{IP:src_ip}/%{INT:src_port} to %{DATA:dst_interface}:%{IP:dst_ip}/%{INT:dst_port}` |

| CiscoASA-710002 |
| ------ |
| **Error Message:** |
|  %ASA-7-710002: \{TCP\|UDP} access permitted from source_address /source_port to interface_name :dest_address /service |
| **Grok Pattern:** |
| `CISCOFW710002 %{WORD:protocol} (?:request\|access) %{CISCO_ACTION:action} from %{IP:src_ip}/%{INT:src_port} to %{DATA:dst_interface}:%{IP:dst_ip}/%{INT:dst_port}` |

| CiscoASA-710003 |
| ------ |
| **Error Message:** |
| %ASA-3-710003: \{TCP\|UDP} access denied by ACL from source_IP/source_port to interface_name :dest_IP/service |
| **Grok Pattern:** |
| `CISCOFW710003 %{WORD:protocol} (?:request\|access) %{CISCO_ACTION:action} from %{IP:src_ip}/%{INT:src_port} to %{DATA:dst_interface}:%{IP:dst_ip}/%{INT:dst_port}` |

| CiscoASA-710005 |
| ------ |
| **Error Message:** |
| %ASA-7-710005: \{TCP\|UDP\|SCTP} request discarded from source_address /source_port to interface_name :dest_address /service |
| **Grok Pattern:** |
| `CISCOFW710005 %{WORD:protocol} (?:request\|access) %{CISCO_ACTION:action} from %{IP:src_ip}/%{INT:src_port} to %{DATA:dst_interface}:%{IP:dst_ip}/%{INT:dst_port}` |

| CiscoASA-710006 |
| ------ |
| **Error Message:** |
| %ASA-7-710006: protocol request discarded from source_address to interface_name :dest_address |
| **Grok Pattern:** |
| `CISCOFW710006 %{WORD:protocol} (?:request\|access) %{CISCO_ACTION:action} from %{IP:src_ip}/%{INT:src_port} to %{DATA:dst_interface}:%{IP:dst_ip}/%{INT:dst_port}` |

| CiscoASA-105009 |
| ------ |
| **Error Message:** |
| %ASA-1-105009: (Primary) Testing on interface interface_name \{Passed\|Failed}. |
| **Grok Pattern:** |
| `CISCOFW105009 \((?:Primary\|Secondary\|Primary_group_2\|Secondary_group_2)\) Testing on [Ii]nterface %{GREEDYDATA:interface_name} Status %{SYSTEMACTIONSTATUS:system_action_status}` |

| CiscoASA-302015 |
| ------ |
| **Error Message:** |
| %ASA-6-302015: Built \{inbound\|outbound} UDP connection number for interface_name :real_address /real_port (mapped_address /mapped_port ) \[(idfw_user )] to interface_name :real_address /real_port (mapped_address /mapped_port )\[(idfw_user )] \[(user )] |
| **Grok Pattern:** |
| `CISCOFW302015 %{CISCO_ACTION:action}(?: %{CISCO_DIRECTION:direction})? %{WORD:protocol} connection %{INT:connection_id} for %{DATA:src_interface}:%{IP:src_ip}/%{INT:src_port}( \(%{IP:src_mapped_ip}/%{INT:src_mapped_port}\))?(\(%{DATA:src_fwuser}\))? to %{DATA:dst_interface}:%{IP:dst_ip}/%{INT:dst_port}( \(%{IP:dst_mapped_ip}/%{INT:dst_mapped_port}\))?(\(%{DATA:dst_fwuser}\))?( duration %{TIME:duration} bytes %{INT:bytes})?(?: %{CISCO_REASON:reason})?( \(%{DATA:user}\))?` |

| CiscoASA-302016 |
| ------ |
| **Error Message:** |
| %ASA-6-302016: Teardown UDP connection number for interface :real-address /real-port \[(idfw_user )] to interface :real-address /real-port \[(idfw_user )] duration hh :mm :ss bytes bytes \[(user )] |
| **Grok Pattern:** |
| `CISCOFW302016 %{CISCO_ACTION:action}(?: %{CISCO_DIRECTION:direction})? %{WORD:protocol} connection %{INT:connection_id} for %{DATA:src_interface}:%{IP:src_ip}/%{INT:src_port}( \(%{IP:src_mapped_ip}/%{INT:src_mapped_port}\))?(\(%{DATA:src_fwuser}\))? to %{DATA:dst_interface}:%{IP:dst_ip}/%{INT:dst_port}( \(%{IP:dst_mapped_ip}/%{INT:dst_mapped_port}\))?(\(%{DATA:dst_fwuser}\))?( duration %{TIME:duration} bytes %{INT:bytes})?(?: %{CISCO_REASON:reason})?( \(%{DATA:user}\))?` |

| CiscoASA-733100 |
| ------ |
| **Error Message:** |
| %ASA-4-733100: Object drop rate rate_ID exceeded. Current burst rate is rate_val per second, max configured rate is rate_val ; Current average rate is rate_val per second, max configured rate is rate_val ; Cumulative total count is total_cnt |
| **Grok Pattern:** |
| `CISCOFW733100 \[\s*%{DATA:drop_type}\s*\] drop %{DATA:drop_rate_id} exceeded. Current burst rate is %{INT:drop_rate_current_burst} per second, max configured rate is %{INT:drop_rate_max_burst}; Current average rate is %{INT:drop_rate_current_avg} per second, max configured rate is %{INT:drop_rate_max_avg}; Cumulative total count is %{INT:drop_total_count}` |

| CiscoASA-106014 |
| ------ |
| **Error Message:** |
| %ASA-3-106014: Deny inbound icmp src interface_name : IP_address \[(\[idfw_user \| FQDN_string ], sg_info )] dst interface_name : IP_address \[(\[idfw_user \| FQDN_string ], sg_info )] (type dec , code dec ) |
| **Grok Pattern:** |
| `CISCOFW106014 %{CISCO_ACTION:action} %{CISCO_DIRECTION:direction} %{WORD:protocol} src %{DATA:src_interface}:%{IP:src_ip}(\(%{DATA:src_fwuser}\))? dst %{DATA:dst_interface}:%{IP:dst_ip}(\(%{DATA:dst_fwuser}\))? \(type %{INT:icmp_type}, code %{INT:icmp_code}\)` |

| CiscoASA-105008 |
| ------ |
| **Error Message:** |
| %ASA-1-105008: (Primary) Testing interface interface_name. |
| **Grok Pattern:** |
| `CISCOFW105008 \((?:%{GREEDYDATA})\) Testing [Ii]nterface %{GREEDYDATA:interface_name}` |

| CiscoASA-105005 |
| ------ |
| **Error Message:** |
| %ASA-1-105005: (Primary) Lost Failover communications with mate on interface interface_name. |
| **Grok Pattern:** |
| `CISCOFW105005 \((?:%{GREEDYDATA})\) Lost Failover communications with mate on [Ii]nterface %{GREEDYDATA:interface_name}` |
