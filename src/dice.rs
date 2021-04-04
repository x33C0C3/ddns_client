use std::error;
use std::fmt;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::net::{AddrParseError, Ipv4Addr};
use std::str::FromStr;

#[derive(Debug)]
pub enum ResponseError {
    CommandError,
    LoginError,
    DbError,
    IpAddressError,
    NoConnection,
    NotFound,
}

impl fmt::Display for ResponseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ResponseError::CommandError => write!(f, "CommandError"),
            ResponseError::LoginError => write!(f, "LoginError"),
            ResponseError::DbError => write!(f, "DbError"),
            ResponseError::IpAddressError => write!(f, "IpAddressError"),
            ResponseError::NoConnection => write!(f, "NoConnection"),
            ResponseError::NotFound => write!(f, "NotFound"),
        }
    }
}

impl error::Error for ResponseError {
    fn description(&self) -> &str {
        match *self {
            ResponseError::CommandError => "Invalid command",
            ResponseError::LoginError => "Login failed",
            ResponseError::DbError => "Database error",
            ResponseError::IpAddressError => "Invalid ip address",
            ResponseError::NoConnection => "Connection error",
            ResponseError::NotFound => "Host or domain name not found",
        }
    }
}

pub fn res_verify(res: &str) -> Result<(), Option<ResponseError>> {
    match res.split(' ').next().unwrap().parse::<i32>() {
        Ok(0) => Ok(()),
        Ok(1) => Err(Some(ResponseError::CommandError)),
        Ok(2) => Err(Some(ResponseError::LoginError)),
        Ok(3) => Err(Some(ResponseError::DbError)),
        Ok(4) => Err(Some(ResponseError::IpAddressError)),
        Ok(5) => Err(Some(ResponseError::NoConnection)),
        Ok(6) => Err(Some(ResponseError::NotFound)),
        _ => Err(None),
    }
}

pub struct Client<T>
where
    T: Read + Write,
{
    stream: BufReader<T>,
    pub verbose: bool,
}

impl<T> Client<T>
where
    T: Read + Write,
{
    pub fn new(stream: T) -> Client<T> {
        Client {
            stream: BufReader::new(stream),
            verbose: false,
        }
    }
}

pub trait Command {
    fn send(&mut self, cmd: &[&str]) -> io::Result<()>;

    fn recv(&mut self, buf: &mut String) -> io::Result<()>;

    fn recv_res(&mut self) -> Result<(), Option<ResponseError>> {
        let mut buf = String::new();
        self.recv(&mut buf).unwrap();
        res_verify(&buf)
    }

    fn call(&mut self, cmd: &[&str]) -> Result<(), Option<ResponseError>> {
        self.send(cmd).unwrap();
        self.recv_res()
    }
}

impl<T> Command for Client<T>
where
    T: Read + Write,
{
    fn send(&mut self, cmd: &[&str]) -> io::Result<()> {
        let mut stream = BufWriter::new(self.stream.get_mut());
        for token in cmd {
            if self.verbose {
                println!("{}", token);
            }
            writeln!(stream, "{}", token)?;
        }
        if self.verbose {
            println!(".");
        }
        writeln!(stream, ".")?;
        Ok(())
    }

    fn recv(&mut self, buf: &mut String) -> io::Result<()> {
        loop {
            let len = buf.len();
            self.stream.read_line(buf)?;
            if self.verbose {
                print!("{}", &buf[len..]);
            }
            if ".\n" == &buf[len..] {
                break;
            }
        }
        Ok(())
    }
}

trait CommandAuth<T> {
    fn send_logout(&mut self) -> Result<(), Option<ResponseError>>;
    fn send_login(&mut self, user: &str, pass: &str) -> Result<(), Option<ResponseError>>;
}

impl<T> CommandAuth<T> for T
where
    T: Command,
{
    fn send_logout(&mut self) -> Result<(), Option<ResponseError>> {
        self.call(&["LOGOUT"])
    }

    fn send_login(&mut self, user: &str, pass: &str) -> Result<(), Option<ResponseError>> {
        match self.call(&[
            "LOGIN",
            &format!("USERID:{}", user),
            &format!("PASSWORD:{}", pass),
        ]) {
            Err(r) => {
                self.send(&["LOGOUT"]).unwrap();
                Err(r)
            }
            Ok(r) => Ok(r),
        }
    }
}

pub trait CommandModip<T> {
    fn send_modip(
        &mut self,
        host: &str,
        dom: &str,
        ipv4: &str,
    ) -> Result<(), Option<ResponseError>>;
}

impl<T> CommandModip<T> for T
where
    T: Command,
{
    fn send_modip(
        &mut self,
        host: &str,
        dom: &str,
        ipv4: &str,
    ) -> Result<(), Option<ResponseError>> {
        match self.call(&[
            "MODIP",
            &format!("HOSTNAME:{}", host),
            &format!("DOMNAME:{}", dom),
            &format!("IPV4:{}", ipv4),
        ]) {
            Err(r) => {
                self.send(&["LOGOUT"]).unwrap();
                Err(r)
            }
            Ok(r) => Ok(r),
        }
    }
}

pub trait ToIpAddrs {
    fn to_ip_addrs(&self) -> Result<Ipv4Addr, AddrParseError>;
}

impl ToIpAddrs for &str {
    fn to_ip_addrs(&self) -> Result<Ipv4Addr, AddrParseError> {
        Ipv4Addr::from_str(self)
    }
}

impl ToIpAddrs for String {
    fn to_ip_addrs(&self) -> Result<Ipv4Addr, AddrParseError> {
        Ipv4Addr::from_str(self)
    }
}

impl ToIpAddrs for Ipv4Addr {
    fn to_ip_addrs(&self) -> Result<Ipv4Addr, AddrParseError> {
        Ok(*self)
    }
}

#[derive(Debug)]
pub struct Information {
    pub user: String,
    pub pass: String,
    pub host: String,
    pub dom: String,
    pub ipaddr: Ipv4Addr,
}

impl Information {
    pub fn new<T: ToIpAddrs>(
        user: impl Into<String>,
        pass: impl Into<String>,
        host: impl Into<String>,
        dom: impl Into<String>,
        ipaddr: T,
    ) -> Information {
        Information {
            user: user.into(),
            pass: pass.into(),
            host: host.into(),
            dom: dom.into(),
            ipaddr: ipaddr.to_ip_addrs().unwrap(),
        }
    }
}

pub trait CommandModipExt<T> {
    fn run_modip(&mut self, info: &Information) -> Result<(), Option<ResponseError>>;
}

impl<T> CommandModipExt<T> for T
where
    T: Command,
{
    fn run_modip(&mut self, info: &Information) -> Result<(), Option<ResponseError>> {
        self.send_login(&info.user, &info.pass)?;
        self.send_modip(&info.host, &info.dom, &info.ipaddr.to_string())?;
        self.send_logout()?;
        Ok(())
    }
}

pub static HOST: &str = "ddnsclient.onamae.com";
pub static PORT: u16 = 65010;
pub static DOMAIN: &str = "ddnsclient.onamae.com";

pub fn open() -> impl Read + Write {
    use openssl::ssl::{SslConnector, SslMethod};
    use std::net::TcpStream;
    use std::time::Duration;
    let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();
    let stream = TcpStream::connect((HOST, PORT)).unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    connector.connect(DOMAIN, stream).unwrap()
}
