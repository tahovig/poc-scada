use std::fs::File;
use std::net::IpAddr;
use std::path::Path;

use etherparse::{NetHeaders, PacketHeaders, TransportHeader};
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub struct Flow {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

impl std::fmt::Display for Flow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{}",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port
        )
    }
}

pub struct Packet {
    pub ts_sec: u32,
    pub flow: Flow,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Pcap(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Pcap(e) => write!(f, "pcap parse error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// Reads a legacy `.pcap` file and returns every TCP/UDP packet with a
/// non-empty payload. Non-IP packets, and IP packets without a TCP/UDP
/// transport layer, are silently skipped.
pub fn read_pcap(path: &Path) -> Result<Vec<Packet>, Error> {
    let file = File::open(path)?;
    let mut reader =
        LegacyPcapReader::new(65536, file).map_err(|e| Error::Pcap(format!("{e:?}")))?;

    let mut packets = Vec::new();

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                if let PcapBlockOwned::Legacy(legacy) = block
                    && let Some(packet) = decode_ethernet_packet(legacy.ts_sec, legacy.data)
                {
                    packets.push(packet);
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader.refill().map_err(|e| Error::Pcap(format!("{e:?}")))?;
            }
            Err(e) => return Err(Error::Pcap(format!("{e:?}"))),
        }
    }

    Ok(packets)
}

fn decode_ethernet_packet(ts_sec: u32, data: &[u8]) -> Option<Packet> {
    let headers = PacketHeaders::from_ethernet_slice(data).ok()?;

    let (src_ip, dst_ip) = match headers.net? {
        NetHeaders::Ipv4(ipv4, _) => (IpAddr::from(ipv4.source), IpAddr::from(ipv4.destination)),
        NetHeaders::Ipv6(ipv6, _) => (IpAddr::from(ipv6.source), IpAddr::from(ipv6.destination)),
        NetHeaders::Arp(_) => return None,
    };

    let (src_port, dst_port) = match headers.transport? {
        TransportHeader::Tcp(tcp) => (tcp.source_port, tcp.destination_port),
        TransportHeader::Udp(udp) => (udp.source_port, udp.destination_port),
        _ => return None,
    };

    let payload = headers.payload.slice();
    if payload.is_empty() {
        return None;
    }

    Some(Packet {
        ts_sec,
        flow: Flow {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        },
        payload: payload.to_vec(),
    })
}
