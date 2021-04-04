use getopts::Options;
use std::env;
use std::fmt;
use std::io::{self, Write};

mod dice;
use dice::{Command, CommandModipExt, ToIpAddrs};

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} IPV4 [options]", program);
    print!("{}", opts.usage(&brief));
}

#[derive(PartialEq, Eq, Debug, Clone, Hash)]
pub enum KEY {
    USER,
    PASS,
    HOST,
    DOM,
}

impl fmt::Display for KEY {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hint = match self {
            KEY::USER => "USERID",
            KEY::PASS => "PASSWORD",
            KEY::HOST => "HOSTNAME",
            KEY::DOM => "DOMNAME",
        };
        write!(f, "{}", hint)
    }
}

impl AsRef<KEY> for KEY {
    fn as_ref(&self) -> &KEY {
        self
    }
}

impl<T> std::ops::Index<T> for dice::Information
where
    T: AsRef<KEY>,
{
    type Output = String;

    fn index(&self, key: T) -> &Self::Output {
        match key.as_ref() {
            KEY::USER => &self.user,
            KEY::PASS => &self.pass,
            KEY::HOST => &self.host,
            KEY::DOM => &self.dom,
        }
    }
}

impl<T> std::ops::IndexMut<T> for dice::Information
where
    T: AsRef<KEY>,
{
    fn index_mut(&mut self, key: T) -> &mut Self::Output {
        match key.as_ref() {
            KEY::USER => &mut self.user,
            KEY::PASS => &mut self.pass,
            KEY::HOST => &mut self.host,
            KEY::DOM => &mut self.dom,
        }
    }
}

fn parse_line(line: &str) -> Option<(KEY, String)> {
    let index = line.find("=")?;
    let key = if line.starts_with("user") {
        KEY::USER
    } else if line.starts_with("pass") {
        KEY::PASS
    } else if line.starts_with("host") {
        KEY::HOST
    } else if line.starts_with("dom") {
        KEY::DOM
    } else {
        return None;
    };
    Some((key, line[index + 1..line.len()].to_owned()))
}

fn main() {
    let mut info = dice::Information::new(
        String::default(),
        String::default(),
        String::default(),
        String::default(),
        std::net::Ipv4Addr::UNSPECIFIED.to_ip_addrs().unwrap(),
    );
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            panic!("{}", f.to_string())
        }
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }
    if 1 > matches.free.len() {
        print_usage(&program, opts);
        return;
    }
    info.ipaddr = match (&matches.free[0]).to_ip_addrs() {
        Ok(addrs) => addrs,
        Err(_) => {
            print_usage(&program, opts);
            return;
        }
    };
    if 1 < matches.free.len() {
        print_usage(&program, opts);
        return;
    }

    if unsafe { 0 != libc::isatty(libc::STDIN_FILENO) } {
        for key in [KEY::USER, KEY::PASS, KEY::HOST, KEY::DOM].iter() {
            let mut value = String::new();
            print!("{}: ", key);
            io::stdout().flush().unwrap();
            io::stdin().read_line(&mut value).unwrap();
            value.pop();
            info[key] = value;
        }
    } else {
        let mut line = String::new();
        loop {
            if 0 == std::io::stdin().read_line(&mut line).unwrap() {
                break;
            };
            line.pop();
            if let Some((key, value)) = parse_line(line.trim_start()) {
                info[key] = value;
            }
            line.clear();
        }
    }
    let mut client = dice::Client::new(dice::open());
    client.verbose = true;
    client.recv_res().unwrap();
    client.run_modip(&info).unwrap();
}
