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

/// Opens a legacy `.pcap` file and returns an iterator over every TCP/UDP
/// packet with a non-empty payload. Non-IP packets, and IP packets without
/// a TCP/UDP transport layer, are silently skipped.
///
/// Packets are decoded one at a time as the iterator is driven, rather than
/// the whole file being read into memory up front — for a multi-hour SCADA
/// capture, holding every packet in memory simultaneously before analysis
/// even starts is real, avoidable memory pressure, not just an abstract
/// concern. The file is still opened (and a malformed pcap header still
/// rejected) eagerly, so a bad path/format fails immediately rather than on
/// first iteration.
pub fn read_pcap(path: &Path) -> Result<PcapPackets, Error> {
    let file = File::open(path)?;
    let reader = LegacyPcapReader::new(65536, file).map_err(|e| Error::Pcap(format!("{e:?}")))?;
    Ok(PcapPackets {
        reader,
        done: false,
    })
}

pub struct PcapPackets {
    reader: LegacyPcapReader<File>,
    /// Set once an unrecoverable error has been yielded, so a caller that
    /// keeps polling past an `Err` (e.g. via `filter_map(Result::ok)`)
    /// can't spin forever re-reading a stream that's already broken.
    done: bool,
}

impl Iterator for PcapPackets {
    type Item = Result<Packet, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        loop {
            match self.reader.next() {
                Ok((offset, block)) => {
                    let decoded = match block {
                        PcapBlockOwned::Legacy(legacy) => {
                            decode_ethernet_packet(legacy.ts_sec, legacy.data)
                        }
                        _ => None,
                    };
                    self.reader.consume(offset);
                    if let Some(packet) = decoded {
                        return Some(Ok(packet));
                    }
                    // Block consumed but wasn't a packet we keep (non-IP,
                    // no TCP/UDP transport, empty payload) — keep scanning.
                }
                Err(PcapError::Eof) => {
                    self.done = true;
                    return None;
                }
                Err(PcapError::Incomplete(_)) => {
                    if let Err(e) = self.reader.refill() {
                        self.done = true;
                        return Some(Err(Error::Pcap(format!("{e:?}"))));
                    }
                }
                Err(e) => {
                    self.done = true;
                    return Some(Err(Error::Pcap(format!("{e:?}"))));
                }
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;

    fn legacy_pcap_bytes(packets: &[(u32, &[u8])]) -> Vec<u8> {
        let mut file_bytes = Vec::new();
        // Legacy pcap global header, microsecond resolution, Ethernet linktype.
        file_bytes.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        file_bytes.extend_from_slice(&2u16.to_le_bytes());
        file_bytes.extend_from_slice(&4u16.to_le_bytes());
        file_bytes.extend_from_slice(&0i32.to_le_bytes());
        file_bytes.extend_from_slice(&0u32.to_le_bytes());
        file_bytes.extend_from_slice(&65535u32.to_le_bytes());
        file_bytes.extend_from_slice(&1u32.to_le_bytes());

        for (ts_sec, tcp_payload) in packets {
            let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
                .ipv4([192, 168, 1, 10], [192, 168, 1, 20], 64)
                .tcp(49152, 20000, 0, 65535);
            let mut packet = Vec::with_capacity(builder.size(tcp_payload.len()));
            builder.write(&mut packet, tcp_payload).unwrap();

            file_bytes.extend_from_slice(&ts_sec.to_le_bytes());
            file_bytes.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
            file_bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes()); // incl_len
            file_bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes()); // orig_len
            file_bytes.extend_from_slice(&packet);
        }

        file_bytes
    }

    fn write_temp_pcap(name: &str, packets: &[(u32, &[u8])]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "poc-scada-core-test-{name}-{}.pcap",
            std::process::id()
        ));
        std::fs::write(&path, legacy_pcap_bytes(packets)).unwrap();
        path
    }

    #[test]
    fn streams_packets_in_order() {
        let path = write_temp_pcap("streams-in-order", &[(1, &[0xAA, 0xBB]), (2, &[0xCC])]);

        let packets: Vec<Packet> = read_pcap(&path)
            .expect("should open")
            .collect::<Result<_, _>>()
            .expect("should decode");

        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].ts_sec, 1);
        assert_eq!(packets[0].payload, vec![0xAA, 0xBB]);
        assert_eq!(packets[1].ts_sec, 2);
        assert_eq!(packets[1].payload, vec![0xCC]);

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn iterator_is_fused_after_eof() {
        let path = write_temp_pcap("fused-after-eof", &[(1, &[0xAA])]);

        let mut iter = read_pcap(&path).expect("should open");
        assert!(iter.next().is_some());
        assert!(iter.next().is_none());
        // Polling again past exhaustion must stay None, not restart or panic.
        assert!(iter.next().is_none());

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn nonexistent_path_fails_immediately() {
        let path = std::env::temp_dir().join("poc-scada-core-test-does-not-exist.pcap");
        assert!(read_pcap(&path).is_err());
    }
}
