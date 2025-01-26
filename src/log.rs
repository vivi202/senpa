use std::error::Error;
use std::fmt::Display;

use crate::ip::{parse_ip_data, parse_ip_header, IpData, IpSpecific};
use crate::packet_filter::parse_packet_filter;
use crate::packet_filter::PacketFilter;
use crate::protocol::parse_proto_info;
use crate::protocol::{ProtoInfo, Protocol};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq)]
pub struct LogParseError {
    pub raw_log: String,
    pub reason: String,
}

impl Display for LogParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "failed to parse: log {}, reason {}",
            self.raw_log, self.reason
        )
    }
}
impl Error for LogParseError {}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
///A struct to represent a firewall log
pub struct FwLog {
    /// Information about the packet filter, such as the rule that triggered the log entry
    /// and the associated interface, action, and direction.
    pub packet_filter: PacketFilter,
    /// Information specific to either IPv4 or IPv6 packets.
    pub ip_specific: IpSpecific,
    /// Packet length and source/destination IP addresses.
    pub ip_data: IpData,
    /// The used protocol (e.g., TCP, UDP)
    pub protocol: Protocol,
    /// Protocol-specific information, including flags and control data.
    pub proto_info: ProtoInfo,
}

/// Parses a single log entry from the given input string.
///
/// This function extracts various components of a log entry, including packet filter details,
/// protocol information, IP header, IP data, and protocol-specific details. If any part of the parsing
/// process fails, an error is returned with a descriptive reason.
///
/// # Arguments
/// - `input`: A string slice representing the raw firewall log entry to be parsed.
///
/// # Returns
/// - `Result<FirewallLogEntry, LogParseError>`: On success, returns the parsed `FirewallLogEntry`.
///   On failure, returns a `LogParseError` with the raw log and the reason for failure.
///
/// # Errors
/// This function returns a `LogParseError` if any of the following parsing steps fail:
/// - Packet filter parsing.
/// - IP header parsing.
/// - IP data parsing.
/// - Protocol-specific information parsing.
///
/// # Example
/// ```rust
/// use senpa::parse_log;
///
/// let input = "example firewall log entry here";
/// let result = parse_log(input);
///
/// match result {
///     Ok(log) => {
///         // Handle the successfully parsed log entry
///         println!("Parsed log entry: {:?}", log);
///     }
///     Err(err) => {
///         // Handle the parsing error
///         eprintln!("Failed to parse log entry: {:?}", err);
///     }
/// }
/// ```
pub fn parse_log(input: &str) -> Result<FwLog, LogParseError> {
    let (next, packet_filter) = parse_packet_filter(input).map_err(|_| LogParseError {
        raw_log: input.into(),
        reason: "Failed to parse packet filter".into(),
    })?;

    let (next, (protocol, ip_header)) = parse_ip_header(next).map_err(|_| LogParseError {
        raw_log: input.into(),
        reason: "Failed to parse IP header".into(),
    })?;

    let (next, ip_data) = parse_ip_data(next, &ip_header).map_err(|_| LogParseError {
        raw_log: input.into(),
        reason: "Failed to parse IP data".into(),
    })?;

    let (_, proto_info) = parse_proto_info(next, &protocol.name).map_err(|_| LogParseError {
        raw_log: input.into(),
        reason: "Failed to parse protocol-specific information".into(),
    })?;

    let firewall_log = FwLog {
        packet_filter,
        ip_specific: ip_header,
        ip_data,
        protocol,
        proto_info,
    };

    Ok(firewall_log)
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::ip::IpV4;
    use crate::packet_filter::Action::*;
    use crate::packet_filter::Dir::*;
    use crate::packet_filter::Reason::*;
    use crate::packet_filter::RuleInfo;
    use crate::protocol::Ports;
    use crate::protocol::ProtoName::*;
    use crate::protocol::TcpInfo;
    use crate::protocol::UdpInfo;
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[test]
    fn it_works_tcp() {
        let log = "96,,,fae559338f65e11c53669fc3642c93c2,vlan0.20,match,pass,out,\
        4,0x0,,127,61633,0,DF,6,tcp,\
        52,192.168.10.15,192.168.20.14,\
        52461,9100,0,S,3442468761,,64240,,mss;nop;wscale;nop;nop;sackOK";
        let flog = parse_log(&log).unwrap();
        assert_eq!(
            FwLog {
                packet_filter: PacketFilter {
                    rule_info: RuleInfo {
                        number: 96,
                        subrulenr: None,
                        anchorname: None,
                        label: "fae559338f65e11c53669fc3642c93c2".into(),
                    },
                    interface: "vlan0.20".into(),
                    reason: Match,
                    action: Pass,
                    dir: Out,
                },
                ip_specific: IpSpecific::IpV4(IpV4 {
                    version: 4,
                    tos: 0,
                    ecn: None,
                    ttl: 127,
                    id: 61633,
                    offset: 0,
                    flags: "DF".into(),
                },),
                ip_data: IpData {
                    length: 52,
                    src: IpAddr::V4(Ipv4Addr::from_str("192.168.10.15").unwrap()),
                    dst: IpAddr::V4(Ipv4Addr::from_str("192.168.20.14").unwrap()),
                },
                protocol: Protocol { num: 6, name: Tcp },
                proto_info: ProtoInfo::TcpInfo(TcpInfo {
                    ports: Ports {
                        srcport: 52461,
                        dstport: 9100,
                    },
                    data_len: 0,
                    flags: "S".into(),
                    sequence_number: "3442468761".into(),
                    ack_number: None,
                    window: 64240,
                    urg: None,
                    options: "mss;nop;wscale;nop;nop;sackOK".into(),
                },),
            },
            flog
        );
    }

    #[test]
    fn it_works_udp() {
        let log = "96,,,fae559338f65e11c53669fc3642c93c2,vlan0.20,match,pass,out,\
        4,0x0,,127,58940,0,none,17,udp,\
        106,192.168.10.15,192.168.20.11,49678,161,86";
        let flog = parse_log(&log).unwrap();
        assert_eq!(
            (FwLog {
                packet_filter: PacketFilter {
                    rule_info: RuleInfo {
                        number: 96,
                        subrulenr: None,
                        anchorname: None,
                        label: "fae559338f65e11c53669fc3642c93c2".into(),
                    },
                    interface: "vlan0.20".into(),
                    reason: Match,
                    action: Pass,
                    dir: Out,
                },
                ip_specific: IpSpecific::IpV4(IpV4 {
                    version: 4,
                    tos: 0,
                    ecn: None,
                    ttl: 127,
                    id: 58940,
                    offset: 0,
                    flags: "none".into(),
                },),
                ip_data: IpData {
                    length: 106,
                    src: IpAddr::V4(Ipv4Addr::from_str("192.168.10.15").unwrap()),
                    dst: IpAddr::V4(Ipv4Addr::from_str("192.168.20.11").unwrap()),
                },
                protocol: Protocol { num: 17, name: Udp },
                proto_info: ProtoInfo::UdpInfo(UdpInfo {
                    ports: Ports {
                        srcport: 49678,
                        dstport: 161,
                    },
                    data_len: 86,
                },),
            }),
            flog
        );
    }

    #[test]
    fn packet_filter_fail() {
        let log = "ab,,,fae559338f65e11c53669fc3642c93c2,vlan0.20,match,pass,out,\
        4,0x0,,127,58940,0,none,17,udp,\
        106,192.168.10.15,192.168.20.11,49678,161,86";
        assert_eq!(
            Err(LogParseError {
                raw_log: log.into(),
                reason: "Failed to parse packet filter".into()
            }),
            parse_log(log)
        );
    }

    #[test]
    fn ip_header_fail() {
        let log = "96,,,fae559338f65e11c53669fc3642c93c2,vlan0.20,match,pass,out,\
        4,0x0,,127ab,58940,0,none,17,udp,\
        106,192.168.10.15,192.168.20.11,49678,161,86";
        assert_eq!(
            Err(LogParseError {
                raw_log: log.into(),
                reason: "Failed to parse IP header".into()
            }),
            parse_log(log)
        );
    }

    #[test]
    fn ip_data_fail() {
        let log = "96,,,fae559338f65e11c53669fc3642c93c2,vlan0.20,match,pass,out,\
        4,0x0,,127,58940,0,none,17,udp,\
        106,192.168.a10.15,192.168.20.11,49678,161,86";
        assert_eq!(
            Err(LogParseError {
                raw_log: log.into(),
                reason: "Failed to parse IP data".into()
            }),
            parse_log(log)
        );
    }

    #[test]
    fn protocol_specific_fail() {
        let log = "96,,,fae559338f65e11c53669fc3642c93c2,vlan0.20,match,pass,out,\
        4,0x0,,127,58940,0,none,17,udp,\
        106,192.168.10.15,192.168.20.11,49678as,161,86";
        assert_eq!(
            Err(LogParseError {
                raw_log: log.into(),
                reason: "Failed to parse protocol-specific information".into()
            }),
            parse_log(log)
        );
    }
}
