# Protocol coverage

This file lists the protocols decoded by EagleEyes and where they are dispatched from.

Link-layer / Datalink
- Ethernet II, IEEE 802.3 + LLC/SNAP (src/protocols/ethernet.rs, llc.rs)
- VLAN 802.1Q (vlan.rs)
- Loopback/Null (loopback.rs, null.rs)
- NFLOG (nflog.rs)
- Bluetooth HCI H4 (bluetooth.rs)
- USB linux (usb.rs)
- SocketCAN (can.rs)
- LIN (lin.rs)
- PPP over Ethernet (pppoe.rs)
- PPP core (ppp.rs) — LCP/IPCP/IPv6CP; IPv4/IPv6 payload dispatch

Network
- IPv4 (ipv4.rs), IPv6 (ipv6.rs)
- ARP (arp.rs)
- IGMP (igmp.rs)
- OSPF (ospf.rs), EIGRP (eigrp.rs)
- IPsec AH/ESP (ah.rs, esp.rs)
- GRE (gre.rs)
- MPLS (mpls.rs)

Transport / Upper
- TCP (tcp.rs), UDP (udp.rs), SCTP (sctp.rs), DCCP (dccp.rs)
- ICMPv4 (icmpv4.rs), ICMPv6 (icmpv6.rs)
- DNS (dns.rs), mDNS (mdns.rs), LLMNR (llmnr.rs)
- DHCP/BOOTP (dhcp.rs), DHCPv6 (dhcpv6.rs)
- NTP (ntp.rs), SNMP (snmp.rs)
- Syslog (syslog.rs)
- QUIC (quic.rs), DoH (doh.rs), DoT (dot.rs)
- HTTP (http.rs), WebSocket (websocket.rs)
- TLS/SSL (tls.rs, ssl.rs)
- FTP/FTPS (ftp.rs, smtps.rs)
- SMTP/SMTPS (smtp.rs, smtps.rs), POP3 (pop3.rs), IMAP/IMAPS (imap.rs)
- LDAP/LDAPS (ldap.rs, ldaps.rs)
- SMB/CIFS (smb.rs), NetBIOS (netbios.rs)
- RDP (rdp.rs)
- TFTP (tftp.rs)
- SIP (sip.rs)
- RTP/RTCP (rtp.rs, rtcp.rs)
- BGP (bgp.rs), RIP (rip.rs)
- Redis (redis.rs), Memcached (memcached.rs)
- MQTT (mqtt.rs), AMQP (amqp.rs), STOMP (stomp.rs)

Datalink dispatch
- capture/from_file select decoders by pcap datalink:
  - EN10MB -> Ethernet
  - NULL/LOOP -> Loopback
  - RAW -> IPv4/IPv6 by version nibble
  - CAN -> SocketCAN
  - NFLOG -> NFLOG
  - BT HCI H4 -> Bluetooth
  - USB (linux) -> USB
  - LIN -> LIN
  - PPP / PPP_BSDOS -> PPP
