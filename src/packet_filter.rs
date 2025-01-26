use std::{error::Error, str::FromStr};

use crate::utils::{csv, parse_utf8_string};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{alphanumeric1, char, u32 as parse_u32},
    combinator::{fail, opt, peek},
    sequence::terminated,
    IResult, Parser,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]

pub enum Dir {
    In,
    Out,
}

#[derive(Debug)]
pub struct ParseDirError;

impl std::fmt::Display for ParseDirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid direction. Expected 'in' or 'out'.")
    }
}

impl Error for ParseDirError {}

impl FromStr for Dir {
    type Err = ParseDirError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "in" => Ok(Dir::In),
            "out" => Ok(Dir::Out),
            _ => Err(ParseDirError),
        }
    }
}

fn parse_dir(input: &str) -> IResult<&str, Dir> {
    let (next, dir) = terminated(alt((tag("in"), tag("out"))), peek(char(',')))(input)?;
    if let Ok(dir) = Dir::from_str(dir) {
        Ok((next, dir))
    } else {
        fail(input)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Reason {
    Match,
}

impl FromStr for Reason {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "match" => Ok(Reason::Match),
            _ => Err(()),
        }
    }
}

fn parse_reason(input: &str) -> IResult<&str, Reason> {
    let (next, reason) = terminated(tag("match"), peek(char(',')))(input)?;

    if let Ok(reason) = Reason::from_str(reason) {
        Ok((next, reason))
    } else {
        fail(input)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Action {
    Pass,
    Block,
    Reject,
}

impl FromStr for Action {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pass" => Ok(Action::Pass),
            "block" => Ok(Action::Block),
            "reject" => Ok(Action::Reject),
            _ => Err(()),
        }
    }
}

fn parse_action(input: &str) -> IResult<&str, Action> {
    let (next, action) = terminated(
        alt((tag("pass"), tag("block"), tag("reject"))),
        peek(char(',')),
    )(input)?;

    if let Ok(action) = Action::from_str(action) {
        Ok((next, action))
    } else {
        fail(input)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RuleInfo {
    pub number: u32,
    pub subrulenr: Option<u32>,
    pub anchorname: Option<String>,
    pub label: String,
}

fn parse_rule_info(input: &str) -> IResult<&str, RuleInfo> {
    let (next, rulenr) = csv(parse_u32)(input)?;
    let (next, subrulenr) = csv(opt(parse_u32))(next)?;
    let (next, anchorname) = csv(opt(alphanumeric1.map(|s: &str| s.into())))(next)?;
    let (next, label) = csv(alphanumeric1).map(|s| s.into()).parse(next)?;

    let rule_info = RuleInfo {
        number: rulenr,
        subrulenr,
        anchorname,
        label,
    };

    Ok((next, rule_info))
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PacketFilter {
    pub rule_info: RuleInfo,
    pub interface: String,
    pub reason: Reason,
    pub action: Action,
    pub dir: Dir,
}

pub(crate) fn parse_packet_filter(input: &str) -> IResult<&str, PacketFilter> {
    let (next, rule_info) = parse_rule_info(input)?;
    let (next, interface) = csv(parse_utf8_string)(next)?;
    let (next, reason) = csv(parse_reason)(next)?;
    let (next, action) = csv(parse_action).parse(next)?;
    let (next, dir) = csv(parse_dir)(next)?;

    Ok((
        next,
        PacketFilter {
            rule_info,
            interface,
            reason,
            action,
            dir,
        },
    ))
}

#[cfg(test)]
mod test {
    use crate::packet_filter::{parse_reason, Dir, Reason};

    use super::*;

    #[test]
    fn test_parse_dir() {
        let in_dir = parse_dir("in,");
        assert_eq!(Ok((",", Dir::In)), in_dir);

        let out_dir = parse_dir("out,");
        assert_eq!(Ok((",", Dir::Out)), out_dir);

        let fail_dir = parse_dir("inner,");
        assert!(fail_dir.is_err());

        let fail_dir = parse_dir("outer,");
        assert!(fail_dir.is_err());

        let fail_dir = parse_dir("wrong,");
        assert!(fail_dir.is_err());
    }

    #[test]
    fn test_parse_reason() {
        let match_reason = parse_reason("match,");
        assert_eq!(Ok((",", Reason::Match)), match_reason);

        let fail_reason = parse_reason("matcha,");
        assert!(fail_reason.is_err());

        let fail_reason = parse_reason("wrong,");
        assert!(fail_reason.is_err());
    }

    #[test]
    fn test_parse_action() {
        let action_pass = parse_action("pass,");
        assert_eq!(Ok((",", Action::Pass)), action_pass);

        let action_pass_fail = parse_action("passerella,");
        assert!(action_pass_fail.is_err());

        let action_block = parse_action("block,");
        assert_eq!(Ok((",", Action::Block)), action_block);

        let action_block_fail = parse_action("blocked,");
        assert!(action_block_fail.is_err());

        let action_reject = parse_action("reject,");
        assert_eq!(Ok((",", Action::Reject)), action_reject);

        let action_block_fail = parse_action("blocked,");
        assert!(action_block_fail.is_err());

        let actio_wrong_fail = parse_action("wrong,");
        assert!(actio_wrong_fail.is_err())
    }

    #[test]
    fn test_parse_rule() {
        let rule_info = "15,,,fae559338f65e11c53669fc3642c93c2,";
        let parsed = parse_rule_info(rule_info);

        assert_eq!(
            Ok((
                "",
                RuleInfo {
                    number: 15,
                    subrulenr: None,
                    anchorname: None,
                    label: "fae559338f65e11c53669fc3642c93c2".into(),
                }
            )),
            parsed
        )
    }

    #[test]
    fn test_parse_packet_filter() {
        let packet_filter = parse_packet_filter(
            "15,,,fae559338f65e11c53669fc3642c93c2,vlan0.20,match,block,in,other,...",
        );
        assert_eq!(
            Ok((
                "other,...",
                PacketFilter {
                    rule_info: RuleInfo {
                        number: 15,
                        subrulenr: None,
                        anchorname: None,
                        label: "fae559338f65e11c53669fc3642c93c2".into()
                    },
                    interface: "vlan0.20".into(),
                    reason: Reason::Match,
                    action: Action::Block,
                    dir: Dir::In
                }
            )),
            packet_filter
        )
    }
}
