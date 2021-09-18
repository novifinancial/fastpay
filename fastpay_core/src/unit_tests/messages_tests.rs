// Copyright (c) Facebook Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::collections::BTreeMap;

#[test]
fn test_signed_values() {
    let mut authorities = BTreeMap::new();
    let key1 = get_key_pair();
    let key2 = get_key_pair();
    let key3 = get_key_pair();
    let name1 = key1.public();
    let name2 = key2.public();

    authorities.insert(name1, /* voting right */ 1);
    authorities.insert(name2, /* voting right */ 0);
    let committee = Committee::new(authorities);

    let request = Request {
        account_id: dbg_account(1),
        operation: Operation::Transfer {
            recipient: Address::FastPay(dbg_account(2)),
            amount: Amount::from(1),
            user_data: UserData::default(),
        },
        sequence_number: SequenceNumber::new(),
    };

    let v = SignedRequest::new(request.clone(), &key1);
    assert!(v.check(&committee).is_ok());

    let v = SignedRequest::new(request.clone(), &key2);
    assert!(v.check(&committee).is_err());

    let v = SignedRequest::new(request, &key3);
    assert!(v.check(&committee).is_err());
}

#[test]
fn test_certificates() {
    let key1 = get_key_pair();
    let key2 = get_key_pair();
    let key3 = get_key_pair();
    let name1 = key1.public();
    let name2 = key2.public();

    let mut authorities = BTreeMap::new();
    authorities.insert(name1, /* voting right */ 1);
    authorities.insert(name2, /* voting right */ 1);
    let committee = Committee::new(authorities);

    let request = Request {
        account_id: dbg_account(1),
        operation: Operation::Transfer {
            recipient: Address::FastPay(dbg_account(1)),
            amount: Amount::from(1),
            user_data: UserData::default(),
        },
        sequence_number: SequenceNumber::new(),
    };

    let v1 = SignedRequest::new(request.clone(), &key1);
    let v2 = SignedRequest::new(request.clone(), &key2);
    let v3 = SignedRequest::new(request.clone(), &key3);

    let mut builder = SignatureAggregator::new(request.clone(), &committee);
    assert!(builder
        .append(v1.authority, v1.signature)
        .unwrap()
        .is_none());
    let mut c = builder.append(v2.authority, v2.signature).unwrap().unwrap();
    assert!(c.check(&committee).is_ok());
    c.signatures.pop();
    assert!(c.check(&committee).is_err());

    let mut builder = SignatureAggregator::new(request, &committee);
    assert!(builder
        .append(v1.authority, v1.signature)
        .unwrap()
        .is_none());
    assert!(builder.append(v3.authority, v3.signature).is_err());
}
