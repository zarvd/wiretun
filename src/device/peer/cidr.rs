use std::net::IpAddr;
use std::str::FromStr;

use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;

#[derive(Clone, Copy, Debug)]
pub struct Cidr(IpNetwork);

impl Cidr {
    pub fn new(ip: IpAddr, mask: u8) -> Self {
        Self(IpNetwork::new_truncate(ip, mask).unwrap())
    }
}

impl ToString for Cidr {
    fn to_string(&self) -> String {
        format!("{}/{}", self.0.network_address(), self.0.netmask())
    }
}

impl From<IpAddr> for Cidr {
    fn from(value: IpAddr) -> Self {
        let mask = match value {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Self::new(value, mask)
    }
}

impl FromStr for Cidr {
    type Err = ParseCidrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((ip, mask)) = s.split_once('/') {
            let ip = IpAddr::from_str(ip).map_err(|_| ParseCidrError::InvalidIp)?;
            let mask = u8::from_str(mask).map_err(|_| ParseCidrError::InvalidMask)?;
            Ok(Self::new(ip, mask))
        } else {
            let ip = IpAddr::from_str(s).map_err(|_| ParseCidrError::InvalidIp)?;
            Ok(Self::from(ip))
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ParseCidrError {
    #[error("invalid ip address")]
    InvalidIp,
    #[error("invalid mask")]
    InvalidMask,
}

pub(super) struct CidrTable<T> {
    table: IpNetworkTable<T>,
}

impl<T> CidrTable<T> {
    pub fn new() -> Self {
        Self {
            table: IpNetworkTable::new(),
        }
    }

    pub fn insert(&mut self, cidr: Cidr, value: T) {
        self.table.insert(cidr.0, value);
    }

    pub fn get_by_ip(&self, ip: IpAddr) -> Option<&T> {
        self.table.longest_match(ip).map(|(_, v)| v)
    }

    pub fn clear(&mut self) {
        self.table = IpNetworkTable::new();
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use ip_network::IpNetwork;
    use ip_network_table::IpNetworkTable;

    #[test]
    fn test() {
        let cidrs = [
            IpNetwork::new_truncate(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 16).unwrap(),
            IpNetwork::new_truncate(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 24).unwrap(),
        ];

        let mut table = IpNetworkTable::new();

        for (i, cidr) in cidrs.iter().enumerate() {
            table.insert(cidr.clone(), i);
        }
        // table.remove(cidrs[0].clone());

        assert_eq!(
            table.longest_match(IpAddr::V4(Ipv4Addr::new(192, 168, 3, 0))),
            Some((cidrs[0].clone(), &0)),
        );
    }
}
