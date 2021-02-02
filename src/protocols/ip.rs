/// Protocol for ip called Assigned Internet Protocol Number
///
/// Assigned Internet protocol number define ip protocol norme
/// These value are defined by IANA
///
/// Sources:
/// * http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
#[non_exhaustive]
pub struct PROTO;

impl PROTO {
    /// IPv6 Hop-by-Hop Option
    pub const HOPOPT: u8 = 0x0;
    /// Internet Control Message
    pub const ICMP: u8 = 0x1;
    /// Internet Group Management
    pub const IGMP: u8 = 0x2;
    /// Internet Group Management
    pub const GGP: u8 = 0x3;
    /// IPv4 encapsulation
    pub const IPV4: u8 = 0x4;
    /// Stream
    pub const ST: u8 = 0x5;
    /// Transimission control
    pub const TCP: u8 = 0x6;
    /// CBT
    pub const CBT: u8 = 0x7;
    /// Exterior Gateway Protocol
    pub const EGP: u8 = 0x8;
    /// any private interior gateway (used by Cisco for their IGRP)
    pub const IGP: u8 = 0x9;
    /// BBN RCC Monitoring
    pub const BNN: u8 = 0xa;
    /// Network Voice Protocol
    pub const NVPII: u8 = 0xb;
    /// PUP
    pub const PUP: u8 = 0xc;
    /// ARGUS
    pub const ARGUS: u8 = 0xd;
    /// EMCON
    pub const EMCON: u8 = 0xe;
    /// Cross net debugger
    pub const XNET: u8 = 0xf;
    /// CHAOS
    pub const CHAOS: u8 = 0x10;
    /// User datagram
    pub const UDP: u8 = 0x11;
    /// Multi plexing
    pub const MUX: u8 = 0x12;
    /// DCN measurement system
    pub const DCN: u8 = 0x13;
    /// Host monitoring
    pub const HMP: u8 = 0x14;
    /// packets radio measurement
    pub const PRM: u8 = 0x15;
    /// xeros ns idp
    pub const XNS: u8 = 0x16;
    /// trunk-1
    pub const TRUNK1: u8 = 0x17;
    /// trunk-2
    pub const TRUNK2: u8 = 0x18;
    /// Leaf 1
    pub const LEAF1: u8 = 0x19;
    /// Leaf 2
    pub const LEAF2: u8 = 0x1a;
    /// Reliable data protocol
    pub const RDP: u8 = 0x1b;
    /// Internet reliable transaction protocol
    pub const IRTP: u8 = 0x1c;
    /// ISO transaction protocol class 4
    pub const ISO4: u8 = 0x1d;
    /// bulk data transfer protocol
    pub const NETBLT: u8 = 0x1e;
    /// MFE network service protocol
    pub const MFENSP: u8 = 0x1f;
    /// MERIT intermodal protocol
    pub const MERITINP: u8 = 0x20;
    /// Datagram congestion control protocol
    pub const DCCP: u8 = 0x21;
    /// Third party connect protocol
    pub const PC3: u8 = 0x22;
    /// inter domain policy routing
    pub const IDPR: u8 = 0x23;
    /// XTP
    pub const XTP: u8 = 0x24;
    /// datagram delivery protocol
    pub const DDP: u8 = 0x25;
    /// Inter-Domain Routing Protocol Control message transport protocol
    pub const IDRPCMTP: u8 = 0x26;
    /// TP++ transport protocol
    pub const TPPP: u8 = 0x27;
    /// IL transport protocol
    pub const IL: u8 = 0x28;
    /// IPV6 encapsulation
    pub const IPV6: u8 = 0x29;
    /// Source demand Routing protocol
    pub const SDRP: u8 = 0x2a;
    /// Routing for IPv6
    pub const IPV6ROUTE: u8 = 0x2b;
    /// Fragment for IPv6
    pub const IPV6FRAG: u8 = 0x2c;
    /// Inter-Domain Routing Protocol
    pub const IDRP: u8 = 0x2d;
    /// Reservation protocol
    pub const RSVP: u8 = 0x2e;
    /// Generic routing encapsulation
    pub const GRE: u8 = 0x2f;
    /// Dynamic source routing protocol
    pub const DSR: u8 = 0x30;
    /// BNA
    pub const BNA: u8 = 0x31;
    /// Encap Security Payload for IPv6
    pub const ESP: u8 = 0x32;
    /// Authentification header for IPv6
    pub const AH: u8 = 0x33;
    /// integrated net layer security TUBA
    pub const INLSP: u8 = 0x34;
    /// SWIPE (deprecated)
    pub const SWIPE: u8 = 0x35;
    /// NBMA Address Resolution Protocol
    pub const NARP: u8 = 0x36;
    /// ip mobility
    pub const MOBILE: u8 = 0x37;
    /// Transport Layer Security Protocol using Kryptonet key management
    pub const TLSP: u8 = 0x38;
    /// SKIP
    pub const SKIP: u8 = 0x39;
    /// ICMP for ipv6
    pub const IPV6ICMP: u8 = 0x3a;
    /// IPV6 no next header
    pub const IPV6NONXT: u8 = 0x3b;
    /// Destination options for IPv6
    pub const IPV6OPTS: u8 = 0x3c;
    /// any host internal protocol
    pub const AHIP: u8 = 0x3d;
    /// CFTP
    pub const CFTP: u8 = 0x3e;
    /// Any local network
    pub const ALN: u8 = 0x3f;
    /// Satnet and backroom EXPAK
    pub const SATEXPAK: u8 = 0x40;
    /// Kryptolan
    pub const KRYPTOLAN: u8 = 0x41;
    /// MIT Remote Virtual Disk Protocol
    pub const RVD: u8 = 0x42;
    /// Internet Pluribus Packet Core
    pub const IPPC: u8 = 0x43;
    /// Any distributed file system
    pub const ANYDFS: u8 = 0x44;
    /// Satnet monitoring
    pub const SATMON: u8 = 0x45;
    /// VISA protocol
    pub const VISA: u8 = 0x46;
    /// Internet packet core protocol
    pub const IPCV: u8 = 0x47;
    /// Computer protocol network executive
    pub const CPNX: u8 = 0x48;
    /// Computer protocol heartbeat
    pub const CPHB: u8 = 0x49;
    /// Wang Span Network
    pub const WSN: u8 = 0x4a;
    /// packet video protocol
    pub const PVP: u8 = 0x4b;
    /// backroom satnet monitoring
    pub const BRSATMON: u8 = 0x4c;
    /// SUN ND PROTOCOL-Temporar
    pub const SUNND: u8 = 0x4d;
    /// WIDEBAND Monitoring
    pub const WBMON: u8 = 0x4e;
    /// WIDEBAND EXPAK
    pub const WBEXPAK: u8 = 0x4f;
    /// ISO internet protocol
    pub const ISOIP: u8 = 0x50;
    /// VMTP
    pub const VMTP: u8 = 0x51;
    /// Secure VMTP
    pub const SVMTP: u8 = 0x52;
    /// VIMES protocol
    pub const VINES: u8 = 0x53;
    /// transaction transport protocol
    pub const IPTM: u8 = 0x54;
    /// NSFNET-IGP
    pub const NSFNETIGP: u8 = 0x55;
    /// Dissimilar Gateway Protocol
    pub const DGP: u8 = 0x56;
    /// TCF protocol
    pub const TCF: u8 = 0x57;
    /// EIGRP protocol
    pub const EIGRP: u8 = 0x58;
    /// OSPFIGP
    pub const OSPFIGP: u8 = 0x59;
    /// Sprite RPC
    pub const SPRITE: u8 = 0x5a;
    /// Locus Address Resolution Protocol
    pub const LARP: u8 = 0x5b;
    /// Multicast Transport Protocol
    pub const MTP: u8 = 0x5c;
    /// AX 25 frames
    pub const AX25: u8 = 0x5d;
    /// IP-within-IP Encapsulation Protocol
    pub const IPIP: u8 = 0x5e;
    /// Mobile Internetworking Control Pro (deprecated)
    pub const MICP: u8 = 0x5f;
    /// Semaphore Communications Sec. Pro.
    pub const SCCSP: u8 = 0x60;
    /// Ethernet-within-IP Encapsulation
    pub const ETHERIP: u8 = 0x61;
    /// Encapsulation header
    pub const ENCAP: u8 = 0x62;
    /// any private encryption scheme
    pub const ANYENCRYPT: u8 = 0x63;
    /// GMTP protocol
    pub const GMTP: u8 = 0x64;
    /// Ipsilon Flow Management Protocol
    pub const IFMP: u8 = 0x65;
    /// PNNI over ip
    pub const PNNI: u8 = 0x66;
    /// Protocol Independent Multicast
    pub const PIM: u8 = 0x67;
    /// ARIS protocol
    pub const ARIS: u8 = 0x68;
    /// SCPS protocol
    pub const SCPS: u8 = 0x69;
    /// QNX
    pub const QNX: u8 = 0x6a;
    /// Active Network
    pub const AN: u8 = 0x6b;
    /// IP Payload Compression Protocol
    pub const IPCOMP: u8 = 0x6c;
    /// Sitara Networks Protocol
    pub const SNP: u8 = 0x6d;
    /// Compaq Peer Protocol
    pub const COMPAQPEER: u8 = 0x6e;
    /// IPX in IP
    pub const IPXIP: u8 = 0x6f;
    /// Virtual Router Redundancy Protocol
    pub const VRRP: u8 = 0x70;
    /// PGM Reliable Transport Protocol
    pub const PGM: u8 = 0x71;
    /// any 0-hop protocol
    pub const ANY0HOP: u8 = 0x72;
    /// Layer Two Tunneling Protocol
    pub const L2TP: u8 = 0x73;
    /// D-II Data Exchange (DDX)
    pub const DDX: u8 = 0x74;
    /// Interactive Agent Transfer Protocol
    pub const IATP: u8 = 0x75;
    /// Schedule Transfer Protocol
    pub const STP: u8 = 0x76;
    /// SpectraLink Radio Protocol
    pub const SRP: u8 = 0x77;
    /// UTI protocol
    pub const UTI: u8 = 0x78;
    /// Simple Message Protocol
    pub const SMP: u8 = 0x79;
    /// Simple Multicast Protocol (deprecated)
    pub const SM: u8 = 0x7a;
    /// Performance Transparency Protocol
    pub const PTP: u8 = 0x7b;
    /// ISIS over IPv4
    pub const ISIS: u8 = 0x7c;
    /// FIRE protocol
    pub const FIRE: u8 = 0x7d;
    /// Combat Radio Transport Protocol
    pub const CRTP: u8 = 0x7e;
    /// Combat Radio User Datagram
    pub const CRUDP: u8 = 0x7f;
    /// SSCOPMCE
    pub const SSCOPMCE: u8 = 0x80;
    /// IPLT
    pub const IPLT: u8 = 0x81;
    /// SPS Secure packet shield
    pub const SPS: u8 = 0x82;
    /// Private IP Encapsulation within IP
    pub const PIPE: u8 = 0x83;
    /// Stream Control Transmission Protocol
    pub const SCTP: u8 = 0x84;
    /// Fibre Channel
    pub const FC: u8 = 0x85;
    /// RSVP-E2E-IGNORE
    pub const RSVPE2EIGNORE: u8 = 0x86;
    /// Mobility header for IPv6
    pub const MOB: u8 = 0x87;
    /// Udp lite protocol
    pub const UDPLITE: u8 = 0x88;
    /// MPLS in IP
    pub const MPLSIP: u8 = 0x89;
    /// MANET Protocols
    pub const MANET: u8 = 0x8a;
    /// Host identity protocol for IPv6
    pub const HIP: u8 = 0x8b;
    /// Shim6 protocol for IPv6
    pub const SHIM6: u8 = 0x8c;
    /// Wrapped Encapsulating Security Payload
    pub const WESP: u8 = 0x8d;
    /// Robust Header Compression
    pub const ROHC: u8 = 0x8e;
    /// Ethernet
    pub const ETHERNET: u8 = 0x8f;
    /// Use for experimental testing for IPv6
    pub const EXP1: u8 = 0xfd;
    /// Use for experimental testing for IPv6
    pub const EXP2: u8 = 0xfe;
    /// Reserved
    pub const RSV: u8 = 0xff;
}

/// Ip protocol code to str
///
/// Transform an u8 to a humain readable str
/// if the value of the given u16 match one of the value in IPV6::Header
/// then a str corresponding to the op code is returned
/// # Examples
/// ```
/// println!(protocol_as_str(0x00));  // will print HOPOPT
/// println!(protocol_as_str(0x2a));  // will print UNKNOW
/// ```
pub fn protocol_as_str(protocol: u8) -> &'static str {
    match protocol {
        PROTO::HOPOPT => "HOPOPT",
        PROTO::ICMP => "ICMP",
        PROTO::IGMP => "IGMP",
        PROTO::GGP => "GGP",
        PROTO::IPV4 => "IPV4",
        PROTO::ST => "ST",
        PROTO::TCP => "TCP",
        PROTO::CBT => "CBT",
        PROTO::EGP => "EGP",
        PROTO::IGP => "IGP",
        PROTO::BNN => "BNN",
        PROTO::NVPII => "NVPII",
        PROTO::PUP => "PUP",
        PROTO::ARGUS => "ARGUS",
        PROTO::XNET => "XNET",
        PROTO::CHAOS => "CHAOS",
        PROTO::UDP => "UDP",
        PROTO::MUX => "MUX",
        PROTO::DCN => "DCN",
        PROTO::HMP => "HMP",
        PROTO::PRM => "PRM",
        PROTO::XNS => "XNS",
        PROTO::TRUNK1 => "TRUNK1",
        PROTO::TRUNK2 => "TRUNK2",
        PROTO::LEAF1 => "LEAF1",
        PROTO::LEAF2 => "LEAF2",
        PROTO::RDP => "RDP",
        PROTO::IRTP => "IRTP",
        PROTO::ISO4 => "ISO4",
        PROTO::NETBLT => "NETBLT",
        PROTO::MFENSP => "MFENSP",
        PROTO::MERITINP => "MERITINP",
        PROTO::DCCP => "DCCP",
        PROTO::PC3 => "3PC",
        PROTO::IDPR => "IDPR",
        PROTO::XTP => "XTP",
        PROTO::DDP => "DDP",
        PROTO::IDRPCMTP => "IDRPCMTP",
        PROTO::TPPP => "TP++",
        PROTO::IL => "IL",
        PROTO::IPV6 => "IPV6",
        PROTO::SDRP => "SDRP",
        PROTO::IPV6ROUTE => "IPV6ROUTE",
        PROTO::IPV6FRAG => "IPV6FRAG",
        PROTO::IDRP => "IDRP",
        PROTO::RSVP => "RSVP",
        PROTO::GRE => "GRE",
        PROTO::DSR => "DSR",
        PROTO::BNA => "BNA",
        PROTO::ESP => "ESP",
        PROTO::AH => "AH",
        PROTO::INLSP => "INLSP",
        PROTO::SWIPE => "SWIPE",
        PROTO::NARP => "NARP",
        PROTO::MOBILE => "MOBILE",
        PROTO::TLSP => "TLSP",
        PROTO::SKIP => "SKIP",
        PROTO::IPV6ICMP => "IPV6ICMP",
        PROTO::IPV6NONXT => "IPV6NONXT",
        PROTO::IPV6OPTS => "IPV6OPTS",
        PROTO::CFTP => "CFTP",
        PROTO::ALN => "ALN",
        PROTO::SATEXPAK => "SATEXPAK",
        PROTO::KRYPTOLAN => "KRYPTOLAN",
        PROTO::RVD => "RVD",
        PROTO::IPPC => "IPPC",
        PROTO::ANYDFS => "ANYDFS",
        PROTO::SATMON => "SATMON",
        PROTO::VISA => "VISA",
        PROTO::IPCV => "IPCV",
        PROTO::CPNX => "CPNX",
        PROTO::CPHB => "CPHB",
        PROTO::WSN => "WSN",
        PROTO::PVP => "PVP",
        PROTO::BRSATMON => "BRSATMON",
        PROTO::SUNND => "SUNND",
        PROTO::WBMON => "WBMON",
        PROTO::WBEXPAK => "WBEXPAK",
        PROTO::ISOIP => "ISOIP",
        PROTO::VMTP => "VMTP",
        PROTO::SVMTP => "SVMTP",
        PROTO::VINES => "VINES",
        PROTO::IPTM => "IPTM",
        PROTO::NSFNETIGP => "NSFNETIGP",
        PROTO::DGP => "DGP",
        PROTO::TCF => "TCF",
        PROTO::EIGRP => "EIGRP",
        PROTO::OSPFIGP => "OSPFIGP",
        PROTO::SPRITE => "SPRITE",
        PROTO::LARP => "LARP",
        PROTO::MTP => "MTP",
        PROTO::AX25 => "AX25",
        PROTO::IPIP => "IPIP",
        PROTO::MICP => "MICP",
        PROTO::SCCSP => "SCCSP",
        PROTO::ETHERIP => "ETHERIP",
        PROTO::ENCAP => "ENCAP",
        PROTO::ANYENCRYPT => "ANYENCRYPT",
        PROTO::GMTP => "GMTP",
        PROTO::IFMP => "IFMP",
        PROTO::PNNI => "PNNI",
        PROTO::PIM => "PIM",
        PROTO::ARIS => "ARIS",
        PROTO::SCPS => "SCPS",
        PROTO::QNX => "QNX",
        PROTO::AN => "AN",
        PROTO::IPCOMP => "IPCOMP",
        PROTO::SNP => "SNP",
        PROTO::COMPAQPEER => "COMPAQPEER",
        PROTO::IPXIP => "IPXIP",
        PROTO::VRRP => "VRRP",
        PROTO::PGM => "PGM",
        PROTO::ANY0HOP => "ANY0HOP",
        PROTO::L2TP => "L2TP",
        PROTO::DDX => "DDX",
        PROTO::IATP => "IATP",
        PROTO::STP => "STP",
        PROTO::SRP => "SRP",
        PROTO::UTI => "UTI",
        PROTO::SMP => "SMP",
        PROTO::SM => "SM",
        PROTO::PTP => "PTP",
        PROTO::ISIS => "ISIS",
        PROTO::FIRE => "FIRE",
        PROTO::CRTP => "CRTP",
        PROTO::CRUDP => "CRUDP",
        PROTO::SSCOPMCE => "SSCOPMCE",
        PROTO::IPLT => "IPLT",
        PROTO::SPS => "SPS",
        PROTO::PIPE => "PIPE",
        PROTO::SCTP => "SCTP",
        PROTO::FC => "FC",
        PROTO::RSVPE2EIGNORE => "RSVPE2EIGNORE",
        PROTO::MOB => "MOB",
        PROTO::UDPLITE => "UDPLITE",
        PROTO::MPLSIP => "MPLSIP",
        PROTO::MANET => "MANET",
        PROTO::HIP => "HIP",
        PROTO::SHIM6 => "SHIM",
        PROTO::WESP => "WESP",
        PROTO::ROHC => "ROHC",
        PROTO::ETHERNET => "ETHERNET",
        PROTO::EXP1 => "EXP1",
        PROTO::EXP2 => "EXP2",
        PROTO::RSV => "RSV",
        _ => "UNKNOW",
    }
}
