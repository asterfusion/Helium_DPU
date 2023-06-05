# Introduction
5G UPF belongs to the important network entity in 5G network, based on VPP framework, reference free5gc/upf for design and implementation, to meet the functional and performance use of operators.

# Feature List

| Service Function | Secondary Function | Description |
| --- | --- | --- |
| N4 session management | UPF and SMF coupling management | N4 session creation, modification and deletion |
| | Session-based information reporting | Collecting usage information for reporting to SMF, specifying PDR traffic reporting |
| | IP address and F-TEID assignment |
| Routing and forwarding features | User-plane data forwarding | Data forwarding for IP sessions, data message segmentation, and performing PDR actions |
| | DiffServ functionality | 5QI or ARP | 
| | Cache management | Marker supports data caching, cache first packet event reporting | 
| | End marker | Construct and send end marker data messages |
| | Precise routing | APN/DNN, L3, L7, URL-based triage | 
| | Tunneling | N3/N9 tunnels encapsulation and decap |
| QoS | QoS tagging | Transport parameter mapping, data flow detection and tagging, reflective QoS mechanism |
| | QoS control | Support QER-based QoS control, rate management, traffic monitoring and control | 
| Service identification function | Data detection and identification | Identify CN, QFI, network instance |
| | Service parsing | PCF/PCRF service data stream, SMF service data stream, protocol identification library |
| | Service identification rules | Identify fields based on L3-L7, extended fields including APN/DNN, URR ID, Application ID |
| Policy enforcement function | Business rules | Traffic processing based on application ID |
| | Traffic gating | Forwarding or dropping of data packets |
| | Usage monitoring and reporting | Based on one or a set of SDF, URR IDs | 
| Reporting of traffic statistics | Traffic thresholds and quotas for reporting, generating PDR/URR |
| Fault management | | Handling and recovery of node failures, session failures and path failures |

# Performance 
- Number of N4 sessions: 500,000
- System throughput: 100Gbps
- Number of DNNs/APNs: 3000
- N3/N9 user-plane sessions: 10 million
