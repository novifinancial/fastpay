// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: Apache-2.0

use super::base_types::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct Committee {
    pub voting_rights: BTreeMap<AuthorityName, usize>,
    pub total_votes: usize,
    pub coconut_setup: Option<CoconutSetup>,
}

#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub struct CoconutSetup {
    pub parameters: coconut::Parameters,
    pub verification_key: coconut::PublicKey,
    pub authorities: BTreeMap<AuthorityName, (/* lagrange index */ u64, coconut::PublicKey)>,
}

impl Committee {
    pub fn new(
        voting_rights: BTreeMap<AuthorityName, usize>,
        coconut_setup: Option<CoconutSetup>,
    ) -> Self {
        let total_votes = voting_rights.iter().fold(0, |sum, (_, votes)| sum + *votes);
        Committee {
            voting_rights,
            total_votes,
            coconut_setup,
        }
    }

    pub fn make_simple(keys: Vec<AuthorityName>) -> Self {
        let total_votes = keys.len();
        Committee {
            voting_rights: keys.into_iter().map(|k| (k, 1)).collect(),
            total_votes,
            coconut_setup: None,
        }
    }

    pub fn weight(&self, author: &AuthorityName) -> usize {
        *self.voting_rights.get(author).unwrap_or(&0)
    }

    pub fn quorum_threshold(&self) -> usize {
        // If N = 3f + 1 + k (0 <= k < 3)
        // then (2 N + 3) / 3 = 2f + 1 + (2k + 2)/3 = 2f + 1 + k = N - f
        2 * self.total_votes / 3 + 1
    }

    pub fn validity_threshold(&self) -> usize {
        // If N = 3f + 1 + k (0 <= k < 3)
        // then (N + 2) / 3 = f + 1 + k/3 = f + 1
        (self.total_votes + 2) / 3
    }

    /// Find the highest value than is supported by a quorum of authorities.
    pub fn get_strong_majority_lower_bound<V>(&self, mut values: Vec<(AuthorityName, V)>) -> V
    where
        V: Default + std::cmp::Ord,
    {
        values.sort_by(|(_, x), (_, y)| V::cmp(y, x));
        // Browse values by decreasing order, while tracking how many votes they have.
        let mut score = 0;
        for (name, value) in values {
            score += self.weight(&name);
            if score >= self.quorum_threshold() {
                return value;
            }
        }
        V::default()
    }
}
