use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use crate::{
    protocol::{ProtoName, Protocol},
    utils::{self, csv, hexadecimal_value},
};

use nom::character::complete::char;
use nom::character::complete::{u16 as parse_u16, u8 as parse_u8};
use nom::{
    branch::alt,
    bytes::complete::{tag, take_till},
    character::complete::alphanumeric1,
    combinator::{fail, opt},
    sequence::separated_pair,
    IResult, Parser,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

fn parse_ipv4_addr(input: &str) -> IResult<&str, Ipv4Addr> {
    let (next, addr) = take_till(|c| c == ',')(input)?;

    match Ipv4Addr::from_str(addr) {
        Ok(addr) => Ok((next, addr)),
        Err(_) => fail(input),
    }
}

fn parse_ipv6_addr(input: &str) -> IResult<&str, Ipv6Addr> {
    let (next, addr) = take_till(|c| c == ',')(input)?;

    match Ipv6Addr::from_str(addr) {
        Ok(addr) => Ok((next, addr)),
        Err(_) => fail(input),
    }
}

fn parse_src_dst_addr<'a>(
    input: &'a str,
    specific: &IpSpecific,
) -> IResult<&'a str, (IpAddr, IpAddr)> {
    match specific {
        IpSpecific::IpV4(_) => {
            let (next, (src, dst)) =
                csv(separated_pair(parse_ipv4_addr, char(','), parse_ipv4_addr))(input)?;

            Ok((next, (IpAddr::V4(src), IpAddr::V4(dst))))
        }

        IpSpecific::Ipv6(_) => {
            let (next, (src, dst)) =
                csv(separated_pair(parse_ipv6_addr, char(','), parse_ipv6_addr))(input)?;
            Ok((next, (IpAddr::V6(src), IpAddr::V6(dst))))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]

pub struct IpData {
    pub length: u16,
    pub src: IpAddr,
    pub dst: IpAddr,
}

pub(crate) fn parse_ip_data<'a>(input: &'a str, specific: &IpSpecific) -> IResult<&'a str, IpData> {
    let (next, length) = csv(parse_u16)(input)?;
    let (next, (src, dst)) = parse_src_dst_addr(next, specific)?;

    Ok((next, IpData { length, src, dst }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum IpSpecific {
    IpV4(IpV4),
    Ipv6(IpV6),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IpV4 {
    pub version: u8,
    pub tos: u8,
    pub ecn: Option<String>,
    pub ttl: u8,
    pub id: u16,
    pub offset: u16,
    pub flags: String,
}

fn parse_ipv4_header(input: &str) -> IResult<&str, (Protocol, IpSpecific)> {
    let (next, tos) = csv(utils::hexadecimal_value)(input)?;
    let (next, ecn) = csv(opt(alphanumeric1.map(|s: &str| s.into())))(next)?;
    let (next, ttl) = csv(parse_u8)(next)?;
    let (next, id) = csv(parse_u16)(next)?;
    let (next, offset) = csv(parse_u16)(next)?;
    let (next, flags) = csv(alphanumeric1).map(|s: &str| s.into()).parse(next)?;
    let (next, protonum) = csv(parse_u8)(next)?;
    let (next, protoname) = csv(alphanumeric1).map(|s: &str| s).parse(next)?;

    let proto = Protocol {
        name: ProtoName::from_str(protoname).unwrap(),
        num: protonum,
    };

    let ipv4 = IpV4 {
        version: 4,
        tos,
        ecn,
        ttl,
        id,
        offset,
        flags,
    };

    Ok((next, (proto, IpSpecific::IpV4(ipv4))))
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]

pub struct IpV6 {
    pub traffic_class: u8,
    pub flow_label: String,
    pub hoplimit: u8,
}

fn parse_ipv6_header(input: &str) -> IResult<&str, (Protocol, IpSpecific)> {
    let (next, traffic_class) = csv(hexadecimal_value)(input)?;
    let (next, flow_label) = csv(alphanumeric1).map(|s: &str| s.into()).parse(next)?;
    let (next, hoplimit) = csv(parse_u8)(next)?;

    let ipv6 = IpV6 {
        traffic_class,
        flow_label,
        hoplimit,
    };

    let (next, protoname) = csv(take_till(|c| c == ','))(next)?;

    let (next, protonum) = csv(parse_u8)(next)?;

    let proto = Protocol {
        name: ProtoName::from_str(protoname).unwrap(),
        num: protonum,
    };

    Ok((next, (proto, IpSpecific::Ipv6(ipv6))))
}

pub(crate) fn parse_ip_header(input: &str) -> IResult<&str, (Protocol, IpSpecific)> {
    let (next, version) = csv(alt((tag("4"), tag("6"))))(input)?;

    match version {
        "4" => parse_ipv4_header(next),
        "6" => parse_ipv6_header(next),
        _ => fail(next),
    }
}
#[cfg(test)]
mod test {
    use super::*;
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        str::FromStr,
    };

    #[test]
    fn parse_ipv4_addr_test() {
        assert_eq!(
            Ok(("", Ipv4Addr::from_str("192.168.10.2").unwrap())),
            parse_ipv4_addr("192.168.10.2")
        )
    }

    #[test]
    fn parse_ipv4_addr_fail() {
        assert!(parse_ipv4_addr("192.168.10.a").is_err())
    }
    #[test]
    fn parse_ipv6_addr_test() {
        assert_eq!(
            Ok((
                "",
                Ipv6Addr::from_str("2001:0db8:85a3:0000:0000:8a2e:0370:7334").unwrap()
            )),
            parse_ipv6_addr("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        )
    }

    #[test]
    fn parse_ipv6_addr_fail() {
        assert!(parse_ipv6_addr("2001:0kb8:85a3:0000:0000:8a2e:0370:7334").is_err())
    }

    #[test]
    fn parse_ip_header_test() {
        let ipv4_header = "4,0x0,,127,58940,0,none,17,udp,\
        106,192.168.10.15,192.168.20.11,49678,161,86";

        let expectedv4 = IpSpecific::IpV4(IpV4 {
            version: 4,
            tos: 0,
            ecn: None,
            ttl: 127,
            id: 58940,
            offset: 0,
            flags: "none".into(),
        });

        assert_eq!(
            Ok((
                "106,192.168.10.15,192.168.20.11,49678,161,86",
                (
                    Protocol {
                        name: ProtoName::Udp,
                        num: 17
                    },
                    expectedv4
                )
            )),
            parse_ip_header(ipv4_header)
        );
    }
}
