use std::str::FromStr;

use nom::bytes::complete::take_till;
use nom::character::complete::{u16 as parse_u16, u32 as parse_u32};
use nom::combinator::rest;
use nom::sequence::terminated;
use nom::Parser;
use nom::{
    combinator::{eof, opt},
    IResult,
};

use crate::utils::{csv, parse_utf8_string};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]

pub struct Protocol {
    pub num: u8, //protonum
    pub name: ProtoName,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]

pub enum ProtoName {
    Tcp,
    Udp,
    Other(String),
}

impl FromStr for ProtoName {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "udp" => Ok(ProtoName::Udp),
            "tcp" => Ok(ProtoName::Tcp),
            other => Ok(ProtoName::Other(other.into())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ports {
    pub srcport: u16,
    pub dstport: u16,
}

pub(crate) fn parse_src_dst_ports(input: &str) -> IResult<&str, Ports> {
    let (next, srcport) = csv(parse_u16)(input)?;
    let (next, dstport) = csv(parse_u16)(next)?;

    Ok((next, Ports { srcport, dstport }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TcpInfo {
    pub ports: Ports,
    pub data_len: u32,
    pub flags: String,
    pub sequence_number: String,
    pub ack_number: Option<u32>,
    pub window: u32,
    pub urg: Option<u32>,
    pub options: String,
}

pub(crate) fn parse_tcp_info(input: &str) -> IResult<&str, ProtoInfo> {
    let (next, ports) = parse_src_dst_ports(input)?;
    let (next, data_len) = csv(parse_u32)(next)?;
    let (next, flags) = csv(parse_utf8_string)(next)?;

    //Todo use a struct to rapresent range
    let (next, sequence_number) = csv(take_till(|c| c == ',')).map(|s| s.into()).parse(next)?;

    let (next, ack_number) = csv(opt(parse_u32))(next)?;
    let (next, window) = csv(parse_u32)(next)?;
    let (next, urg) = csv(opt(parse_u32))(next)?;
    let (next, options) = rest(next).map(|f| (f.0, f.1.into()))?;

    let tcp_info = TcpInfo {
        ports,
        data_len,
        flags,
        sequence_number,
        ack_number,
        window,
        urg,
        options,
    };

    Ok((next, ProtoInfo::TcpInfo(tcp_info)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UdpInfo {
    pub ports: Ports,
    pub data_len: u32,
}

pub(crate) fn parse_udp_info(input: &str) -> IResult<&str, ProtoInfo> {
    let (next, ports) = parse_src_dst_ports(input)?;
    let (next, data_len) = terminated(parse_u32, eof)(next)?;

    Ok((next, ProtoInfo::UdpInfo(UdpInfo { ports, data_len })))
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CarpInfo {}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ProtoInfo {
    UdpInfo(UdpInfo),
    TcpInfo(TcpInfo),
    //TODO CarpInfo(CarpInfo),
    UnknownInfo(String),
}

pub(crate) fn parse_proto_info<'a>(
    input: &'a str,
    proto: &ProtoName,
) -> IResult<&'a str, ProtoInfo> {
    let (next, proto_info) = match proto {
        ProtoName::Tcp => parse_tcp_info(input)?,
        ProtoName::Udp => parse_udp_info(input)?,
        ProtoName::Other(_) => terminated(parse_utf8_string, eof)
            .map(ProtoInfo::UnknownInfo)
            .parse(input)?,
    };

    Ok((next, proto_info))
}

#[cfg(test)]
mod test {}
