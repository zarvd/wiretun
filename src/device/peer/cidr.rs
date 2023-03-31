use std::net::IpAddr;
use std::str::FromStr;

use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;

fn max_mask_for_ip(ip: &IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

#[derive(Clone, Copy, Debug, Hash)]
pub struct Cidr(IpNetwork);

impl Cidr {
    /// # Panics
    /// Panics if the mask is invalid for the given IP address.
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
        let mask = max_mask_for_ip(&value);
        Self::new(value, mask)
    }
}

impl PartialEq for Cidr {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for Cidr {}

impl FromStr for Cidr {
    type Err = ParseCidrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((ip, mask)) = s.split_once('/') {
            let ip = IpAddr::from_str(ip).map_err(|_| ParseCidrError::InvalidIp)?;
            let mask = u8::from_str(mask).map_err(|_| ParseCidrError::InvalidMask)?;
            if mask > max_mask_for_ip(&ip) {
                return Err(ParseCidrError::InvalidMask);
            }

            Ok(Self::new(ip, mask))
        } else {
            let ip = IpAddr::from_str(s).map_err(|_| ParseCidrError::InvalidIp)?;
            Ok(Self::from(ip))
        }
    }
}

#[derive(thiserror::Error, Debug, PartialEq)]
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

    pub fn remove(&mut self, cidr: Cidr) {
        self.table.remove(cidr.0);
    }

    pub fn clear(&mut self) {
        self.table = IpNetworkTable::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_str_for_cidr() {
        let valid_cases = [
            ("10.2.3.4", "10.2.3.4/32"),
            ("10.2.3.4/32", "10.2.3.4/32"),
            ("10.2.3.4/16", "10.2.0.0/16"),
            ("10.2.3.4/24", "10.2.3.0/24"),
        ];

        for (input, expected) in valid_cases {
            let cidr = Cidr::from_str(input);
            assert!(cidr.is_ok());
            let cidr = cidr.unwrap();
            assert_eq!(cidr.to_string(), expected);
        }

        let invalid_cases = [
            ("10.2.3.4.", ParseCidrError::InvalidIp),
            ("10.2.3.256", ParseCidrError::InvalidIp),
            ("10.0.0.1/33", ParseCidrError::InvalidMask),
            ("10.0.0.1/32/", ParseCidrError::InvalidMask),
        ];

        for (input, expected) in invalid_cases {
            let cidr = Cidr::from_str(input);
            assert!(cidr.is_err());
            assert_eq!(cidr.unwrap_err(), expected);
        }
    }

    #[test]
    fn test_cidr_table_get_by_id() {
        let mut table = CidrTable::new();
        table.insert("10.2.3.4/16".parse().unwrap(), 1);
        assert_eq!(table.get_by_ip("10.2.0.0".parse().unwrap()), Some(&1));
        assert_eq!(table.get_by_ip("10.2.1.0".parse().unwrap()), Some(&1));
        assert_eq!(table.get_by_ip("10.2.255.0".parse().unwrap()), Some(&1));

        assert_eq!(table.get_by_ip("10.3.0.0".parse().unwrap()), None);
        assert_eq!(table.get_by_ip("10.1.0.0".parse().unwrap()), None);
        table.insert("10.3.0.0/16".parse().unwrap(), 2);
        assert_eq!(table.get_by_ip("10.3.0.0".parse().unwrap()), Some(&2));
        assert_eq!(table.get_by_ip("10.1.0.0".parse().unwrap()), None);

        assert_eq!(table.get_by_ip("10.2.0.0".parse().unwrap()), Some(&1));
        assert_eq!(table.get_by_ip("10.2.1.0".parse().unwrap()), Some(&1));
        assert_eq!(table.get_by_ip("10.2.255.0".parse().unwrap()), Some(&1));
    }
}
