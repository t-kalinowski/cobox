use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use std::net::TcpListener;
use std::net::TcpStream;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::time::Duration;

pub fn run(mut args: impl Iterator<Item = String>) -> Result<()> {
    let denied = args.next().context("binding expectation")? == "denied";
    let address = args.next().context("outbound address")?.parse()?;
    println!("started");
    let bound = TcpListener::bind("127.0.0.1:0");
    let datagram = UdpSocket::bind("127.0.0.1:0");
    if denied {
        ensure!(
            bound.err().and_then(|error| error.raw_os_error()) == Some(libc::EPERM),
            "mandatory bind denial was not enforced"
        );
        ensure!(
            datagram.err().and_then(|error| error.raw_os_error()) == Some(libc::EPERM),
            "mandatory datagram bind denial was not enforced"
        );
    } else {
        bound.context("ordinary local binding")?;
        datagram.context("ordinary datagram binding")?;
    }
    // listen() can implicitly bind an otherwise unbound IP socket. Check that
    // route separately, while connect() must still get an ephemeral local port.
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    ensure!(socket >= 0, "create listen probe socket");
    let socket = unsafe { OwnedFd::from_raw_fd(socket) };
    let listening = unsafe { libc::listen(socket.as_raw_fd(), 1) };
    if denied {
        ensure!(
            listening == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM),
            "mandatory listen denial was not enforced"
        );
    } else {
        ensure!(listening == 0, "ordinary local listening");
    }
    println!("{}", if denied { "binding-denied" } else { "bound" });
    TcpStream::connect_timeout(&address, Duration::from_secs(3))
        .context("permitted outbound connection")?;
    println!("connected");
    Ok(())
}
