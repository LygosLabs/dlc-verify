//! Bitcoin networks, identified by the chain hash an offer names.

use bitcoin::Network;

/// The networks a DLC offer may name, in the order they are tried.
pub const NETWORKS: [Network; 5] = [
    Network::Bitcoin,
    Network::Testnet,
    Network::Testnet4,
    Network::Signet,
    Network::Regtest,
];

/// The chain hash DDK writes into an offer for `network`: the genesis block hash in internal
/// byte order.
pub fn chain_hash(network: Network) -> [u8; 32] {
    bitcoin::blockdata::constants::ChainHash::using_genesis_block_const(network).to_bytes()
}

/// How an offer's chain hash matched a network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainMatch {
    /// The network.
    pub network: Network,
    /// Whether the hash was written in display (reversed) byte order rather than the order DDK
    /// writes. DDK rejects such offers, so this is reported, not accepted.
    pub reversed: bool,
}

/// The network an offer's chain hash names, if any.
pub fn network_from_chain_hash(hash: &[u8; 32]) -> Option<ChainMatch> {
    NETWORKS.into_iter().find_map(|network| {
        let expected = chain_hash(network);
        if *hash == expected {
            return Some(ChainMatch {
                network,
                reversed: false,
            });
        }
        let mut reversed = expected;
        reversed.reverse();
        (*hash == reversed).then_some(ChainMatch {
            network,
            reversed: true,
        })
    })
}

/// The lowercase name used in reports and on the command line.
pub fn network_name(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "mainnet",
        Network::Testnet => "testnet",
        Network::Testnet4 => "testnet4",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
    }
}

/// Parses a network name: `mainnet` (or `bitcoin`), `testnet`, `testnet4`, `signet` or `regtest`.
pub fn parse_network(name: &str) -> Option<Network> {
    match name.trim().to_ascii_lowercase().as_str() {
        "mainnet" | "bitcoin" | "main" => Some(Network::Bitcoin),
        "testnet" | "testnet3" => Some(Network::Testnet),
        "testnet4" => Some(Network::Testnet4),
        "signet" => Some(Network::Signet),
        "regtest" => Some(Network::Regtest),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_network_round_trips() {
        for network in NETWORKS {
            let hash = chain_hash(network);
            assert_eq!(
                network_from_chain_hash(&hash),
                Some(ChainMatch {
                    network,
                    reversed: false
                })
            );
            let mut reversed = hash;
            reversed.reverse();
            assert_eq!(
                network_from_chain_hash(&reversed),
                Some(ChainMatch {
                    network,
                    reversed: true
                })
            );
            assert_eq!(parse_network(network_name(network)), Some(network));
        }
    }

    #[test]
    fn unknown_hash() {
        assert_eq!(network_from_chain_hash(&[7; 32]), None);
    }
}
