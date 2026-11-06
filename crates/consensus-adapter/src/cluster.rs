//! Four full-view nodes. Agreement here is the application vote rule
//! (≥⌈2n/3⌉ `Valid` on the same `id(v)`). It is not Malachite networking.

use std::path::Path;

use clob::Genesis;
use commitments::{value_id, Digest};
use protocol_types::{ConsensusValue, Input};

use crate::node::{FullViewNode, NodeError};
use crate::port::Validity;

#[derive(Debug)]
pub enum ClusterError {
    Node(NodeError),
    NoQuorum,
}

impl From<NodeError> for ClusterError {
    fn from(e: NodeError) -> Self {
        Self::Node(e)
    }
}

impl std::fmt::Display for ClusterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Node(e) => write!(f, "{e}"),
            Self::NoQuorum => write!(f, "no 2/3 Valid on one value"),
        }
    }
}

impl std::error::Error for ClusterError {}

pub struct Cluster {
    pub nodes: Vec<FullViewNode>,
}

impl Cluster {
    pub fn open_four(dir: impl AsRef<Path>, genesis: Genesis) -> Result<Self, ClusterError> {
        let dir = dir.as_ref();
        let mut nodes = Vec::with_capacity(4);
        for i in 0..4u8 {
            let wal = dir.join(format!("n{i}.wal"));
            nodes.push(FullViewNode::open(wal, [i + 1; 32], genesis.clone())?);
        }
        Ok(Self { nodes })
    }

    /// Honest prevotes; decide if ≥3 `Valid` on the proposer's `id(v)`.
    pub fn vote(&mut self, value: &ConsensusValue, inputs: &[Option<&[Input]>]) -> Vec<Validity> {
        self.nodes
            .iter_mut()
            .zip(inputs.iter())
            .map(|(n, i)| n.validate_proposal(value, *i))
            .collect()
    }

    pub fn valid_count(votes: &[Validity]) -> usize {
        votes.iter().filter(|v| **v == Validity::Valid).count()
    }

    pub fn quorum(n: usize) -> usize {
        (n * 2).div_ceil(3)
    }
}

/// Proposer = node 0. All listed `I` slices are the same batch or `None`.
pub fn run_height(
    cluster: &mut Cluster,
    inputs: &[Input],
    have_i: [bool; 4],
) -> Result<Digest, ClusterError> {
    let value = cluster.nodes[0].get_value(inputs);
    let offered: Vec<Option<&[Input]>> = have_i
        .iter()
        .map(|h| if *h { Some(inputs) } else { None })
        .collect();
    let votes = cluster.vote(&value, &offered);
    if Cluster::valid_count(&votes) < Cluster::quorum(cluster.nodes.len()) {
        return Err(ClusterError::NoQuorum);
    }
    let id = value_id(&value);
    for (node, has) in cluster.nodes.iter_mut().zip(have_i.iter()) {
        if *has {
            node.decide(&value, inputs)?;
        }
    }
    Ok(id)
}
