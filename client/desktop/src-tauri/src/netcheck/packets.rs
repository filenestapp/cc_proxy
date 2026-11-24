use super::{elapsed, Failure, NetworkReading, Resolution, SERVICE};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

const UDP_TIMEOUT: Duration = Duration::from_millis(1800);
const STUN_COOKIE: [u8; 4] = 0x2112_A442_u32.to_be_bytes();
const GOOGLE_DNS: [u8; 4] = [8, 8, 8, 8];
const CLOUDFLARE_DNS: [u8; 4] = [1, 1, 1, 1];

fn socket(peer: SocketAddr) -> Result<UdpSocket, Failure> {
    let local = if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(local)?;
    socket.connect(peer)?;
    socket.set_read_timeout(Some(UDP_TIMEOUT))?;
    socket.set_write_timeout(Some(UDP_TIMEOUT))?;
    Ok(socket)
}

fn system_ipv4(host: &str) -> Result<Vec<IpAddr>, Failure> {
    let mut addrs: Vec<_> = (host, 443)
        .to_socket_addrs()
        .map_err(|_| Failure::Dns)?
        .filter_map(|address| address.is_ipv4().then_some(address.ip()))
        .collect();
    addrs.sort_unstable();
    addrs.dedup();
    Ok(addrs)
}

pub(super) fn is_fake_ip(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(ip) if matches!(ip.octets(), [198, 18 | 19, ..]))
}

pub(super) fn stun(host: &'static str, port: u16, family: u8) -> NetworkReading {
    let mut row = NetworkReading {
        method: "stun",
        server: host,
        family: Some(family),
        ..NetworkReading::default()
    };
    let result = (|| -> Result<(), Failure> {
        let peer = (host, port)
            .to_socket_addrs()
            .map_err(|_| Failure::Dns)?
            .find(|addr| addr.is_ipv4() == (family == 4))
            .ok_or(Failure::Dns)?;
        let socket = socket(peer)?;
        let mut request = [0; 20];
        request[1] = 1; // STUN Binding request
        request[4..8].copy_from_slice(&STUN_COOKIE);
        getrandom::fill(&mut request[8..]).map_err(|_| Failure::Network)?;
        let mut buffer = [0; 2048];
        let start = Instant::now();
        socket.send(&request)?;
        let len = socket.recv(&mut buffer)?;
        row.ms = Some(elapsed(start));
        row.ip = Some(stun_address(&buffer[..len], &request[8..]).ok_or(Failure::InvalidResponse)?);
        Ok(())
    })();
    row.error = result.err();
    row
}

fn stun_address(packet: &[u8], transaction: &[u8]) -> Option<IpAddr> {
    if packet.get(..2)? != [1, 1]
        || packet.get(4..8)? != STUN_COOKIE
        || packet.get(8..20)? != transaction
    {
        return None;
    }
    let end = 20 + usize::from(word(packet, 2)?);
    let packet = packet.get(..end)?;
    let mut cursor = 20;
    let mut mapped = None;
    while cursor < end {
        let kind = word(packet, cursor)?;
        let length = usize::from(word(packet, cursor + 2)?);
        let body = packet.get(cursor + 4..cursor + 4 + length)?;
        cursor += 4 + length.next_multiple_of(4);
        if cursor > end {
            return None;
        }
        let xor = matches!(kind, 0x0020 | 0x8020);
        if !xor && kind != 0x0001 {
            continue;
        }
        let size = match body.get(1)? {
            1 => 4,
            2 => 16,
            _ => continue,
        };
        let mut address = [0; 16];
        address[..size].copy_from_slice(body.get(4..size + 4)?);
        if xor {
            for (byte, mask) in address[..size]
                .iter_mut()
                .zip(STUN_COOKIE.iter().chain(transaction))
            {
                *byte ^= mask;
            }
        }
        let ip = if size == 4 {
            IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&address[..4]).ok()?))
        } else {
            IpAddr::V6(Ipv6Addr::from(address))
        };
        if xor {
            return Some(ip);
        }
        mapped = Some(ip);
    }
    mapped
}

enum Answer {
    Address(IpAddr),
    Text(String),
}

fn word(packet: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        packet.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn dns_request(
    server: [u8; 4],
    name: &str,
    kind: u16,
    class: u16,
) -> Result<(Vec<Answer>, f64), Failure> {
    let socket = socket(SocketAddr::from((server, 53)))?;
    let mut id = [0; 2];
    getrandom::fill(&mut id).map_err(|_| Failure::Network)?;
    let mut request = Vec::from(id);
    request.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for part in name.split('.') {
        request.push(
            part.len()
                .try_into()
                .map_err(|_| Failure::InvalidResponse)?,
        );
        request.extend_from_slice(part.as_bytes());
    }
    request.push(0);
    request.extend_from_slice(&kind.to_be_bytes());
    request.extend_from_slice(&class.to_be_bytes());

    let start = Instant::now();
    socket.send(&request)?;
    let mut packet = [0; 4096];
    let len = socket.recv(&mut packet)?;
    let answers = dns_answers(&packet[..len], id).ok_or(Failure::InvalidResponse)?;
    Ok((answers, elapsed(start)))
}

fn skip_name(packet: &[u8], mut cursor: usize) -> Option<usize> {
    loop {
        let size = *packet.get(cursor)?;
        match size {
            0 => return Some(cursor + 1),
            0xC0..=0xFF => {
                let pointer = usize::from(word(packet, cursor)? & 0x3FFF);
                return (pointer < packet.len()).then_some(cursor + 2);
            }
            1..=63 => cursor += 1 + usize::from(size),
            _ => return None,
        }
    }
}

fn dns_text(mut data: &[u8]) -> Option<String> {
    let mut text = Vec::new();
    while let Some((&length, rest)) = data.split_first() {
        let length = usize::from(length);
        text.extend_from_slice(rest.get(..length)?);
        data = rest.get(length..)?;
    }
    String::from_utf8(text).ok()
}

fn dns_answers(packet: &[u8], id: [u8; 2]) -> Option<Vec<Answer>> {
    let flags = word(packet, 2)?;
    if packet.get(..2)? != id || flags & 0x820F != 0x8000 || packet.len() < 12 {
        return None;
    }
    let mut cursor = 12;
    for _ in 0..word(packet, 4)? {
        cursor = skip_name(packet, cursor)? + 4;
        packet.get(..cursor)?;
    }
    let mut answers = Vec::new();
    for _ in 0..word(packet, 6)? {
        cursor = skip_name(packet, cursor)?;
        let kind = word(packet, cursor)?;
        let size = usize::from(word(packet, cursor + 8)?);
        cursor += 10;
        let data = packet.get(cursor..cursor + size)?;
        cursor += size;
        match kind {
            1 if size == 4 => answers.push(Answer::Address(
                Ipv4Addr::from(<[u8; 4]>::try_from(data).ok()?).into(),
            )),
            28 if size == 16 => answers.push(Answer::Address(
                Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?).into(),
            )),
            16 => answers.push(Answer::Text(dns_text(data)?)),
            _ => {}
        }
    }
    Some(answers)
}

fn subnet(text: &str) -> Option<(IpAddr, u8)> {
    let (ip, prefix) = text.split_once('/')?;
    let ip: IpAddr = ip.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    (prefix <= if ip.is_ipv4() { 32 } else { 128 }).then_some((ip, prefix))
}

pub(super) fn dns() -> (Vec<NetworkReading>, Vec<NetworkReading>) {
    let mut system = NetworkReading {
        method: "system",
        server: "whoami.akamai.net",
        ..NetworkReading::default()
    };
    let start = Instant::now();
    match system_ipv4(system.server) {
        Ok(addresses) => {
            let ip = addresses.first().copied();
            system.fake = ip.is_some_and(is_fake_ip);
            system.ip = ip.filter(|ip| !is_fake_ip(*ip));
            if ip.is_none() {
                system.error = Some(Failure::NoResponse);
            }
        }
        Err(error) => system.error = Some(error),
    }
    system.ms = Some(elapsed(start));

    let mut google = NetworkReading {
        method: "google",
        server: "8.8.8.8",
        ..NetworkReading::default()
    };
    let mut udp = Vec::new();
    match dns_request(GOOGLE_DNS, "o-o.myaddr.l.google.com", 16, 1) {
        Ok((answers, ms)) => {
            google.ms = Some(ms);
            for answer in answers {
                let Answer::Text(text) = answer else { continue };
                if let Some((ip, prefix)) =
                    text.strip_prefix("edns0-client-subnet ").and_then(subnet)
                {
                    google.ecs = Some(format!("{ip}/{prefix}"));
                    udp.push(NetworkReading {
                        method: "google-ecs",
                        server: google.server,
                        family: Some(if ip.is_ipv4() { 4 } else { 6 }),
                        ip: Some(ip),
                        ms: Some(ms),
                        ..NetworkReading::default()
                    });
                } else if let Ok(ip) = text.parse() {
                    google.ip = Some(ip);
                }
            }
            if google.ip.is_none() && google.ecs.is_none() {
                google.error = Some(Failure::NoResponse);
            }
        }
        Err(error) => google.error = Some(error),
    }

    let mut cloudflare = NetworkReading {
        method: "cloudflare-dns",
        server: "1.1.1.1",
        family: Some(4),
        ..NetworkReading::default()
    };
    match dns_request(CLOUDFLARE_DNS, "whoami.cloudflare", 16, 3) {
        Ok((answers, ms)) => {
            cloudflare.ms = Some(ms);
            cloudflare.ip = answers.into_iter().find_map(|answer| match answer {
                Answer::Text(text) => text.parse().ok(),
                _ => None,
            });
            if cloudflare.ip.is_none() {
                cloudflare.error = Some(Failure::NoResponse);
            }
        }
        Err(error) => cloudflare.error = Some(error),
    }
    udp.push(cloudflare);
    (vec![system, google], udp)
}

pub(super) fn resolutions() -> Vec<Resolution> {
    let public = dns_request(CLOUDFLARE_DNS, SERVICE, 1, 1)
        .map(|(answers, _)| {
            answers
                .into_iter()
                .filter_map(|answer| match answer {
                    Answer::Address(ip) => Some(ip),
                    _ => None,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    ["claude.ai", "chatgpt.com", "www.google.com", SERVICE]
        .into_iter()
        .map(|host| Resolution {
            host,
            system: system_ipv4(host).unwrap_or_default(),
            public: if host == SERVICE {
                public.clone()
            } else {
                Vec::new()
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_stun_xor_address_and_checks_the_transaction() {
        let transaction = [7; 12];
        let mut packet = vec![1, 1, 0, 12];
        packet.extend(STUN_COOKIE);
        packet.extend(transaction);
        packet.extend([0, 0x20, 0, 8, 0, 1, 0, 0]);
        packet.extend(
            [203, 0, 113, 8]
                .into_iter()
                .zip(STUN_COOKIE)
                .map(|(ip, mask)| ip ^ mask),
        );
        assert_eq!(
            stun_address(&packet, &transaction),
            Some(Ipv4Addr::new(203, 0, 113, 8).into())
        );
        assert_eq!(stun_address(&packet, &[8; 12]), None);
        assert_eq!(
            stun_address(&packet[..packet.len() - 1], &transaction),
            None
        );
    }

    #[test]
    fn reads_dns_answers_and_rejects_incomplete_packets() {
        let mut packet = vec![4, 2, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        packet.extend([4, b't', b'e', b's', b't', 0, 0, 1, 0, 1]);
        packet.extend([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 9]);
        let result = dns_answers(&packet, [4, 2]).unwrap();
        assert!(
            matches!(&result[..], [Answer::Address(ip)] if *ip == IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)))
        );
        assert!(dns_answers(&packet, [0, 2]).is_none());
        assert!(dns_answers(&packet[..packet.len() - 1], [4, 2]).is_none());
        assert_eq!(dns_text(&[2, b'o', b'k', 1, b'!']).as_deref(), Some("ok!"));
    }
}
