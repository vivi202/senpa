# Senpa
`Senpa` is a parser for OPNsense firewall logs(maybe it also work for pfsense).

# Features 
The serde feature adds Serde Serialize and Deserialize traits to Log.

# How to parse a log?
```rust
    use senpa::prelude::*;

    let log= "96,,,fae559338f65e11c53669fc3642c93c2,vlan0.20,match,pass,out,\
    4,0x0,,127,61633,0,DF,6,tcp,\
    52,192.168.10.15,192.168.20.14,\
    52461,9100,0,S,3442468761,,64240,,mss;nop;wscale;nop;nop;sackOK";
    
    match parse_log(&log){
        Ok(parsed_log) => {
            println!("# LOG #");
            println!("rule number: {} ",parsed_log.packet_filter.rule_info.number);
            assert_eq!(96,parsed_log.packet_filter.rule_info.number);

            println!("rule label: {} ",&parsed_log.packet_filter.rule_info.label);
            assert_eq!("fae559338f65e11c53669fc3642c93c2",&parsed_log.packet_filter.rule_info.label);

            match &parsed_log.packet_filter.action {
                Pass => println!("Action: Pass"),
                Block => println!("Action: Block"),
                Reject => println!("Action: Reject"),
            }
            assert_eq!(Pass,parsed_log.packet_filter.action);

            match &parsed_log.protocol.name {
                Tcp => println!("Proto: tcp"),
                Udp => println!("Proto: udp"),
                Other(other) => println!("Proto: {}",other),
            }
            assert_eq!(Tcp,parsed_log.protocol.name);

            match &parsed_log.proto_info {
                UdpInfo(udp_info) => println!("ProtoInfo:{:#?}",udp_info),
                TcpInfo(tcp_info) => println!("ProtoInfo:{:#?}",tcp_info),
                UnknownInfo(unknown) => println!("ProtoInfo: {}",unknown),
            }
            assert!(matches!(parsed_log.proto_info,TcpInfo(_)));
            
        }
        Err(e) => {
            println!("{}",e);
        }
    }

```
