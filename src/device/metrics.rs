use std::collections::HashMap;

use super::peer::PeerMetrics;

pub struct DeviceMetrics {
    pub peers: HashMap<[u8; 32], PeerMetrics>, // index by public key
}
