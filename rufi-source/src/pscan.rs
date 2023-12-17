use futures::{stream, StreamExt};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    time::Duration,
};
use tokio::net::TcpStream;

#[tokio::main]
pub async fn scanner(target: &str) -> Result<(), anyhow::Error> {
    println!("Scanning {} for all 65535 ports", target);
    let socket_addresses: Vec<SocketAddr> = format!("{}:0", target).to_socket_addrs()?.collect();

    if socket_addresses.is_empty() {
        return Err(anyhow::anyhow!("Socket address list is empty"));
    }

    scan(socket_addresses[0].ip(), 1002, 30).await;
    Ok(())
}

async fn scan(target: IpAddr, concurrency: usize, timeout: u64) {
    let ports = stream::iter(get_ports());

    ports
        .for_each_concurrent(concurrency, |port| scan_port(target, port, timeout))
        .await;
}

async fn scan_port(target: IpAddr, port: u16, timeout: u64) {
    let timeout = Duration::from_secs(timeout);
    let socket_address = SocketAddr::new(target.clone(), port);

    match tokio::time::timeout(timeout, TcpStream::connect(&socket_address)).await {
        Ok(Ok(_)) => {
            print_ports(port);
        }
        _ => {}
    }
}

fn get_ports() -> Box<dyn Iterator<Item = u16>> {
    Box::new((1..=u16::MAX).into_iter())
}

fn print_ports(port: u16) {
    let port_map: HashMap<u16, &str> = [
        (80, "HTTP"),
        (8080, "HTTP"),
        (88, "Kerberos"),
        (443, "HTTPS/SSL"),
        (8443, "HTTPS/SSL"),
        (20, "FTP"),
        (21, "FTP"),
        (22, "SSH/FTPS"),
        (23, "Telnet"),
        (25, "SMTP"),
        (26, "SMTP"),
        (53, "DNS"),
        (69, "TFTP"),
        (110, "POP3"),
        (137, "SMB"),
        (139, "SMB"),
        (143, "IMAP"),
        (389, "LDAP"),
        (445, "Active Directory/SMB"),
        (587, "SMTP SSL"),
        (636, "LDAPS"),
        (993, "IMAP SSL"),
        (995, "POP3 SSL"),
        (2049, "NFS"),
        (2077, "WebDAV/WebDisk"),
        (2078, "WebDAV/WebDisk SSL"),
        (2082, "cPanel"),
        (2083, "cPanel SSL"),
        (2086, "WHM"),
        (2095, "WebMail"),
        (2096, "WebMail SSL"),
        (3268, "ActiveDirectory LDAP"),
        (3269, "ActiveDirectory LDAPS"),
        (3306, "MySQL"),
        (4172, "PCoIP (AWS)"),
        (5000, "UPnP"),
        (5555, "Android Debug Bridge"),
    ]
    .iter()
    .cloned()
    .collect();

    if let Some(service) = port_map.get(&port) {
        println!("\x1B[32mOpen Port:\x1B[0m {} ({})", port, service);
    } else {
        println!("\x1B[32mOpen Port:\x1B[0m {}", port);
    }
}


