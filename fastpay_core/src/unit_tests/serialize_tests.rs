// Copyright (c) Facebook Inc.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::same_item_push)] // get_key_pair returns random elements

use super::*;
use crate::base_types::*;
use std::time::Instant;

#[test]
fn test_error() {
    let err = FastPayError::UnknownSigner;
    let buf = serialize_error(&err);
    let result = deserialize_message(buf.as_slice());
    assert!(result.is_ok());
    if let SerializedMessage::Error(o) = result.unwrap() {
        assert!(*o == err);
    } else {
        panic!()
    }
}

#[test]
fn test_info_query() {
    let query1 = AccountInfoQuery {
        account_id: dbg_account(0x20),
        query_sequence_number: None,
        query_received_requests_excluding_first_nth: None,
    };
    let query2 = AccountInfoQuery {
        account_id: dbg_account(0x20),
        query_sequence_number: Some(SequenceNumber::from(129)),
        query_received_requests_excluding_first_nth: None,
    };

    let buf1 = serialize_info_query(&query1);
    let buf2 = serialize_info_query(&query2);

    let result1 = deserialize_message(buf1.as_slice());
    let result2 = deserialize_message(buf2.as_slice());
    assert!(result1.is_ok());
    assert!(result2.is_ok());

    if let SerializedMessage::InfoQuery(o) = result1.unwrap() {
        assert!(*o == query1);
    } else {
        panic!()
    }
    if let SerializedMessage::InfoQuery(o) = result2.unwrap() {
        assert!(*o == query2);
    } else {
        panic!()
    }
}

#[test]
fn test_order() {
    let sender_key = get_key_pair();

    let request = Request {
        account_id: dbg_account(1),
        operation: Operation::Transfer {
            recipient: Address::FastPay(dbg_account(0x20)),
            amount: Amount::from(5),
            user_data: UserData::default(),
        },
        sequence_number: SequenceNumber::new(),
    };
    let request_order = RequestOrder::new(request, &sender_key);

    let buf = serialize_request_order(&request_order);
    let result = deserialize_message(buf.as_slice());
    assert!(result.is_ok());
    if let SerializedMessage::Order(o) = result.unwrap() {
        assert!(*o == request_order);
    } else {
        panic!()
    }

    let sender_key = get_key_pair();
    let request2 = Request {
        account_id: dbg_account(1),
        operation: Operation::Transfer {
            recipient: Address::FastPay(dbg_account(0x20)),
            amount: Amount::from(5),
            user_data: UserData::default(),
        },
        sequence_number: SequenceNumber::new(),
    };
    let request_order2 = RequestOrder::new(request2, &sender_key);

    let buf = serialize_request_order(&request_order2);
    let result = deserialize_message(buf.as_slice());
    assert!(result.is_ok());
    if let SerializedMessage::Order(o) = result.unwrap() {
        assert!(*o == request_order2);
    } else {
        panic!()
    }
}

#[test]
fn test_vote() {
    let request = Request {
        account_id: dbg_account(1),
        operation: Operation::Transfer {
            recipient: Address::Primary(dbg_addr(0x20)),
            amount: Amount::from(5),
            user_data: UserData::default(),
        },
        sequence_number: SequenceNumber::new(),
    };
    let key = get_key_pair();
    let vote = SignedRequest::new(request, &key);

    let buf = serialize_vote(&vote);
    let result = deserialize_message(buf.as_slice());
    assert!(result.is_ok());
    if let SerializedMessage::Vote(o) = result.unwrap() {
        assert!(*o == vote);
    } else {
        panic!()
    }
}

#[test]
fn test_cert() {
    let request = Request {
        account_id: dbg_account(1),
        operation: Operation::Transfer {
            recipient: Address::Primary(dbg_addr(0x20)),
            amount: Amount::from(5),
            user_data: UserData::default(),
        },
        sequence_number: SequenceNumber::new(),
    };
    let mut cert = CertifiedRequest {
        value: request,
        signatures: Vec::new(),
    };

    for _ in 0..3 {
        let key = get_key_pair();
        let sig = Signature::new(&cert.value, &key);

        cert.signatures.push((key.public(), sig));
    }

    let buf = serialize_cert(&cert);
    let result = deserialize_message(buf.as_slice());
    assert!(result.is_ok());
    if let SerializedMessage::Confirmation(o) = result.unwrap() {
        assert!(*o == cert);
    } else {
        panic!()
    }
}

#[test]
fn test_info_response() {
    let sender_key = get_key_pair();
    let request = Request {
        account_id: dbg_account(1),
        operation: Operation::Transfer {
            recipient: Address::Primary(dbg_addr(0x20)),
            amount: Amount::from(5),
            user_data: UserData::default(),
        },
        sequence_number: SequenceNumber::new(),
    };
    let auth_key = get_key_pair();
    let vote = SignedRequest::new(request.clone(), &auth_key);

    let mut cert = CertifiedRequest {
        value: request,
        signatures: Vec::new(),
    };

    for _ in 0..3 {
        let key = get_key_pair();
        let sig = Signature::new(&cert.value, &key);

        cert.signatures.push((key.public(), sig));
    }

    let resp1 = AccountInfoResponse {
        account_id: dbg_account(0x20),
        owner: Some(sender_key.public()),
        balance: Balance::from(50),
        next_sequence_number: SequenceNumber::new(),
        pending_confirmation: None,
        queried_certificate: None,
        queried_received_requests: Vec::new(),
    };
    let resp2 = AccountInfoResponse {
        account_id: dbg_account(0x20),
        owner: None,
        balance: Balance::from(50),
        next_sequence_number: SequenceNumber::new(),
        pending_confirmation: Some(vote.clone()),
        queried_certificate: None,
        queried_received_requests: Vec::new(),
    };
    let resp3 = AccountInfoResponse {
        account_id: dbg_account(0x20),
        owner: None,
        balance: Balance::from(50),
        next_sequence_number: SequenceNumber::new(),
        pending_confirmation: None,
        queried_certificate: Some(cert.clone()),
        queried_received_requests: Vec::new(),
    };
    let resp4 = AccountInfoResponse {
        account_id: dbg_account(0x20),
        owner: None,
        balance: Balance::from(50),
        next_sequence_number: SequenceNumber::new(),
        pending_confirmation: Some(vote),
        queried_certificate: Some(cert),
        queried_received_requests: Vec::new(),
    };

    for resp in [resp1, resp2, resp3, resp4].iter() {
        let buf = serialize_info_response(resp);
        let result = deserialize_message(buf.as_slice());
        assert!(result.is_ok());
        if let SerializedMessage::InfoResponse(o) = result.unwrap() {
            assert!(*o == *resp);
        } else {
            panic!()
        }
    }
}

#[test]
fn test_time_order() {
    let sender_key = get_key_pair();
    let request = Request {
        account_id: dbg_account(1),
        operation: Operation::Transfer {
            recipient: Address::Primary(dbg_addr(0x20)),
            amount: Amount::from(5),
            user_data: UserData::default(),
        },
        sequence_number: SequenceNumber::new(),
    };

    let mut buf = Vec::new();
    let now = Instant::now();
    for _ in 0..100 {
        let request_order = RequestOrder::new(request.clone(), &sender_key);
        serialize_request_order_into(&mut buf, &request_order).unwrap();
    }
    println!("Write Order: {} microsec", now.elapsed().as_micros() / 100);

    let mut buf2 = buf.as_slice();
    let now = Instant::now();
    let owner = Some(sender_key.public());
    for _ in 0..100 {
        if let SerializedMessage::Order(order) = deserialize_message(&mut buf2).unwrap() {
            order.check(&owner).unwrap();
        }
    }
    assert!(deserialize_message(&mut buf2).is_err());
    println!(
        "Read & Check Order: {} microsec",
        now.elapsed().as_micros() / 100
    );
}

#[test]
fn test_time_vote() {
    let request = Request {
        account_id: dbg_account(1),
        operation: Operation::Transfer {
            recipient: Address::Primary(dbg_addr(0x20)),
            amount: Amount::from(5),
            user_data: UserData::default(),
        },
        sequence_number: SequenceNumber::new(),
    };

    let key = get_key_pair();

    let mut buf = Vec::new();
    let now = Instant::now();
    for _ in 0..100 {
        let vote = SignedRequest::new(request.clone(), &key);
        serialize_vote_into(&mut buf, &vote).unwrap();
    }
    println!("Write Vote: {} microsec", now.elapsed().as_micros() / 100);

    let mut buf2 = buf.as_slice();
    let now = Instant::now();
    for _ in 0..100 {
        if let SerializedMessage::Vote(vote) = deserialize_message(&mut buf2).unwrap() {
            vote.signature.check(&vote.value, vote.authority).unwrap();
        }
    }
    assert!(deserialize_message(&mut buf2).is_err());
    println!(
        "Read & Quickcheck Vote: {} microsec",
        now.elapsed().as_micros() / 100
    );
}

#[test]
fn test_time_cert() {
    let count = 100;
    let request = Request {
        account_id: dbg_account(1),
        operation: Operation::Transfer {
            recipient: Address::Primary(dbg_addr(0)),
            amount: Amount::from(5),
            user_data: UserData::default(),
        },
        sequence_number: SequenceNumber::new(),
    };
    let mut cert = CertifiedRequest {
        value: request,
        signatures: Vec::new(),
    };

    for _ in 0..7 {
        let key = get_key_pair();
        let sig = Signature::new(&cert.value, &key);
        cert.signatures.push((key.public(), sig));
    }

    let mut buf = Vec::new();
    let now = Instant::now();

    for _ in 0..count {
        serialize_cert_into(&mut buf, &cert).unwrap();
    }
    println!("Write Cert: {} microsec", now.elapsed().as_micros() / count);

    let now = Instant::now();
    let mut buf2 = buf.as_slice();
    for _ in 0..count {
        if let SerializedMessage::Confirmation(cert) = deserialize_message(&mut buf2).unwrap() {
            Signature::verify_batch(&cert.value, &cert.signatures).unwrap();
        }
    }
    assert!(deserialize_message(buf2).is_err());
    println!(
        "Read & Quickcheck Cert: {} microsec",
        now.elapsed().as_micros() / count
    );
}
