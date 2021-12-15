# pcap_replay
Replay the pcap with scapy

# Requirements
CentOS 6+

# Usage
1. Move pcap_replay directory into /opt  
2. Copy your pcap document to /opt/pcap_replay  
3. Change the mode of /opt/pcap_replay/fast_py38_install.sh to 777  
4. sh /opt/pcap_replay/fast_py38_install.sh download  
5. Fill in the blanks in /opt/pcap_replay/config.yaml  
6. sh /opt/pcap_replay/fast_py38_install.sh activate  
7. Then your packages from pcap will resend to the ip:port set in config.yaml.  
