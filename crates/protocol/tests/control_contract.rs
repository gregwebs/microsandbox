//! Control conformance fixtures and adversarial checked-decoder boundaries.

use std::path::PathBuf;

use ciborium::Value;
use microsandbox_protocol::{
    codec::{self, MAX_FRAME_SIZE},
    control::*,
    message::{Message, MessageType},
    wire::{self, Envelope, WireError},
};
use microsandbox_types::{
    Action, Destination, Direction, NetworkPolicy, PortRange, Protocol, Rule,
};
use serde_json::{Value as JsonValue, json};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn bytes(value: &Value) -> Vec<u8> {
    wire::encode(value).unwrap()
}

fn field(name: &str, value: Value) -> (Value, Value) {
    (Value::Text(name.into()), value)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The tenant policy pinned by the network-policy-replace golden bytes.
fn probe_policy() -> NetworkPolicy {
    NetworkPolicy {
        default_egress: Action::Deny,
        default_ingress: Action::Allow,
        rules: vec![Rule {
            direction: Direction::Egress,
            destination: Destination::Domain("probe.example".into()),
            protocols: vec![Protocol::Tcp],
            ports: vec![PortRange {
                start: 443,
                end: 443,
            }],
            action: Action::Allow,
        }],
    }
}

/// One `control.network-policy.replace` payload shaped exactly as `fields` describes.
fn policy_envelope(policy: Value) -> Envelope {
    Envelope {
        v: 2,
        t: "control.network-policy.replace".into(),
        p: bytes(&Value::Map(vec![field("policy", policy)])),
    }
}

fn probe_rule() -> Value {
    Value::Map(vec![
        field("direction", "egress".into()),
        field(
            "destination",
            Value::Map(vec![field("domain", "probe.example".into())]),
        ),
        field("action", "allow".into()),
    ])
}

fn case(name: &str, envelope: Envelope, id: u32, flags: u8) -> JsonValue {
    raw_case(name, envelope.frame(id, flags).unwrap())
}

fn raw_case(name: &str, raw: codec::RawFrame) -> JsonValue {
    let envelope = Envelope::decode(&raw.body).unwrap();
    let mut frame = Vec::new();
    codec::encode_raw_to_buf(&raw, &mut frame).unwrap();
    json!({
        "name": name, "generation": envelope.v, "type": envelope.t,
        "id": raw.id, "flags": raw.flags, "payload_hex": hex(&envelope.p),
        "envelope_hex": hex(&raw.body), "frame_hex": hex(&frame),
    })
}

fn fixtures() -> JsonValue {
    let hello = ControlHello {
        min_generation: 1,
        max_generation: 1,
        ..Default::default()
    };
    let welcome = ControlWelcome::negotiate(&hello, DEFAULT_MAX_IN_FLIGHT).unwrap();
    let mut cases = vec![
        case(
            "hello",
            Envelope::new(1, "control.hello", &hello).unwrap(),
            0,
            0,
        ),
        case(
            "welcome",
            Envelope::new(1, "control.welcome", &welcome).unwrap(),
            0,
            1,
        ),
    ];
    for (name, request) in [
        ("capabilities", ControlRequest::Capabilities),
        ("memory_query", ControlRequest::MemoryState),
        ("cpu_query", ControlRequest::CpuState),
        (
            "memory_target",
            ControlRequest::MemoryTarget { total_mib: 2048 },
        ),
        (
            "memory_target_u64",
            ControlRequest::MemoryTarget {
                total_mib: u64::MAX,
            },
        ),
        ("cpu_target", ControlRequest::CpuTarget { online: 2 }),
        (
            "secrets_update",
            ControlRequest::SecretsUpdate {
                changes: vec![
                    SecretChange::Rotate {
                        name: "TEST_KEY".into(),
                        value: SecretValue("fixture-only".into()),
                    },
                    SecretChange::Remove {
                        name: "OLD_KEY".into(),
                    },
                    SecretChange::SetAllowedHosts {
                        name: "TEST_KEY".into(),
                        hosts: vec!["example.test".into()],
                    },
                ],
            },
        ),
    ] {
        cases.push(case(name, request.envelope(1).unwrap(), 17, 0));
    }
    cases.push(case(
        "capabilities_result",
        Envelope::new(
            1,
            "control.capabilities.result",
            &Capabilities {
                root_disk_grow: false,
                cpu_resize: true,
                memory_resize: true,
                secrets_update: false,
            },
        )
        .unwrap(),
        17,
        1,
    ));
    cases.push(case(
        "memory_state",
        Envelope::new(
            1,
            "control.memory.state",
            &MemoryState {
                boot_mib: 512,
                target_mib: 2048,
                current_mib: 1024,
                max_mib: 4096,
            },
        )
        .unwrap(),
        17,
        1,
    ));
    cases.push(case(
        "memory_state_u64",
        Envelope::new(
            1,
            "control.memory.state",
            &MemoryState {
                boot_mib: 1,
                target_mib: (1u64 << 53) + 1,
                current_mib: 0,
                max_mib: u64::MAX,
            },
        )
        .unwrap(),
        17,
        1,
    ));
    cases.push(case(
        "cpu_state",
        Envelope::new(
            1,
            "control.cpu.state",
            &CpuState {
                possible: 4,
                requested_online: 2,
                actual_online: 1,
                enforced: 2,
            },
        )
        .unwrap(),
        17,
        1,
    ));
    cases.push(case(
        "secrets_complete",
        Envelope::new(
            1,
            "control.secrets.result",
            &SecretsResult::Complete { applied_count: 3 },
        )
        .unwrap(),
        17,
        1,
    ));
    cases.push(case(
        "secrets_failed",
        Envelope::new(
            1,
            "control.secrets.result",
            &SecretsResult::Failed {
                applied_count: 1,
                failed_index: 1,
                error: ControlError::rejected("unknown_secret", "unknown secret"),
            },
        )
        .unwrap(),
        17,
        1,
    ));
    for code in [
        "invalid_handshake",
        "unsupported_generation",
        "invalid_request",
        "unsupported_operation",
        "busy",
        "unknown_secret",
        "invalid_secret_hosts",
        "internal",
    ] {
        let id = if matches!(code, "invalid_handshake" | "unsupported_generation") {
            0
        } else {
            17
        };
        cases.push(case(
            code,
            Envelope::new(
                1,
                "control.error",
                &ControlError::rejected(code, "operation rejected"),
            )
            .unwrap(),
            id,
            1,
        ));
    }
    cases.push(case(
        "unknown_error_effect",
        Envelope::new(
            1,
            "control.error",
            &ControlError {
                code: "future_error".into(),
                message: "result unavailable".into(),
                effect: ErrorEffect::Unknown,
            },
        )
        .unwrap(),
        17,
        1,
    ));
    let future_memory = Value::Map(vec![
        field("boot_mib", 512u64.into()),
        field("target_mib", 2048u64.into()),
        field("current_mib", 1024u64.into()),
        field("max_mib", 4096u64.into()),
        field(
            "future",
            Value::Map(vec![field("opaque", Value::Bytes(vec![0, 255]))]),
        ),
    ]);
    let envelope = Envelope::new(1, "control.memory.state", &future_memory).unwrap();
    cases.push(case(
        "memory_state_future_payload_field",
        envelope.clone(),
        17,
        1,
    ));
    // A checked envelope view drops extension fields. Pin the original body
    // separately so cross-language raw forwarding must preserve both layers.
    cases.push(raw_case(
        "memory_state_future_envelope_field",
        codec::RawFrame {
            id: 17,
            flags: 1,
            body: bytes(&Value::Map(vec![
                field("v", 1u64.into()),
                field("t", envelope.t.into()),
                field("p", Value::Bytes(envelope.p)),
                field("future", Value::Bytes(vec![1, 0, 255])),
            ])),
        },
    ));
    json!({"protocol": "msb.control", "generation": 1, "cases": cases})
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn generation_one_bytes_match_cross_language_fixtures() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/control-v1.json");
    let actual = fixtures();
    if std::env::var_os("UPDATE_CONTROL_FIXTURES").is_some() {
        // Only a source checkout can update the shared corpus. Packaged tests
        // read their exact local copy and must not create files outside the crate.
        let shared = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../packages/protocol-fixtures/control-v1.json");
        assert!(shared.is_file(), "update fixtures from a source checkout");
        let encoded = format!("{}\n", serde_json::to_string_pretty(&actual).unwrap());
        std::fs::write(&shared, &encoded).unwrap();
        std::fs::write(&path, &encoded).unwrap();
    }
    let expected: JsonValue = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        actual, expected,
        "control wire bytes changed; review compatibility before updating fixtures"
    );
}

#[test]
fn neutral_envelope_preserves_existing_agent_encoding() {
    let original = Message::with_payload(
        MessageType::ExecStdin,
        42,
        &microsandbox_protocol::exec::ExecStdin {
            data: b"input\0\xff".to_vec(),
        },
    )
    .unwrap();
    let neutral = Envelope {
        v: original.v,
        t: original.t.as_str().into(),
        p: original.p.clone(),
    };
    let mut agent_bytes = Vec::new();
    codec::encode_to_buf(&original, &mut agent_bytes).unwrap();
    let mut neutral_bytes = Vec::new();
    codec::encode_raw_to_buf(
        &neutral.frame(original.id, original.flags).unwrap(),
        &mut neutral_bytes,
    )
    .unwrap();
    assert_eq!(agent_bytes, neutral_bytes);
}

#[test]
fn checked_decoder_rejects_trailing_and_duplicate_keys() {
    let duplicate = bytes(&Value::Map(vec![
        field("total_mib", 1u64.into()),
        field("total_mib", 2u64.into()),
    ]));
    assert_eq!(
        wire::decode_record::<MemoryTarget>(&duplicate),
        Err(WireError::DuplicateKey)
    );
    let mut trailing = wire::encode(&MemoryTarget { total_mib: 1 }).unwrap();
    trailing.push(0);
    assert_eq!(
        wire::decode_record::<MemoryTarget>(&trailing),
        Err(WireError::InvalidCbor)
    );
}

#[test]
fn checked_decoder_ignores_future_fields_but_rejects_duplicate_unknown_keys() {
    let future = field(
        "future",
        Value::Map(vec![(Value::Integer(1.into()), Value::Bytes(vec![0, 255]))]),
    );
    let valid = bytes(&Value::Map(vec![
        field("total_mib", 2048u64.into()),
        future.clone(),
    ]));
    assert_eq!(
        wire::decode_record::<MemoryTarget>(&valid)
            .unwrap()
            .total_mib,
        2048
    );
    let duplicate = bytes(&Value::Map(vec![
        field("total_mib", 1u64.into()),
        future.clone(),
        future,
    ]));
    assert_eq!(
        wire::decode_record::<MemoryTarget>(&duplicate),
        Err(WireError::DuplicateKey)
    );
}

#[test]
fn pinned_future_fields_decode_as_checked_memory_and_survive_raw_forwarding() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/control-v1.json");
    let fixtures: JsonValue = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    for name in [
        "memory_state_future_payload_field",
        "memory_state_future_envelope_field",
    ] {
        let fixture = fixtures["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|fixture| fixture["name"] == name)
            .expect("the future-field case must be pinned");
        let packet = fixture["frame_hex"].as_str().unwrap();
        let mut input = (0..packet.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&packet[index..index + 2], 16).unwrap())
            .collect();
        let frame = codec::try_decode_raw_from_buf(&mut input).unwrap().unwrap();
        assert!(input.is_empty());
        let envelope = Envelope::decode(&frame.body).unwrap();
        assert_eq!(
            envelope.payload::<MemoryState>().unwrap(),
            MemoryState {
                boot_mib: 512,
                target_mib: 2048,
                current_mib: 1024,
                max_mib: 4096,
            }
        );
        let mut forwarded = Vec::new();
        codec::encode_raw_to_buf(&frame, &mut forwarded).unwrap();
        assert_eq!(hex(&forwarded), packet);
        if name == "memory_state_future_envelope_field" {
            assert_ne!(envelope.encode().unwrap(), frame.body);
        }
    }
}

#[test]
fn unsigned_fields_reject_negative_floats_strings_and_overflow() {
    for value in [
        Value::Integer((-1).into()),
        Value::Float(1.0),
        Value::Text("1".into()),
        Value::Bool(true),
    ] {
        let encoded = bytes(&Value::Map(vec![field("total_mib", value)]));
        assert!(wire::decode_record::<MemoryTarget>(&encoded).is_err());
    }
    let encoded = bytes(&Value::Map(vec![field(
        "online",
        (u32::MAX as u64 + 1).into(),
    )]));
    assert!(wire::decode_record::<CpuTarget>(&encoded).is_err());
    let encoded = wire::encode(&MemoryTarget {
        total_mib: u64::MAX,
    })
    .unwrap();
    assert_eq!(
        wire::decode_record::<MemoryTarget>(&encoded)
            .unwrap()
            .total_mib,
        u64::MAX
    );
}

#[test]
fn handshake_limits_and_generation_are_validated_in_both_directions() {
    let mut hello = ControlHello {
        max_generation: 7,
        max_frame_size: 8192,
        max_in_flight: 8,
        ..Default::default()
    };
    let welcome = ControlWelcome::negotiate(&hello, 4).unwrap();
    assert_eq!(
        (
            welcome.generation,
            welcome.max_frame_size,
            welcome.max_in_flight
        ),
        (2, 8192, 4)
    );
    welcome.validate_for(&hello).unwrap();
    let mut bad = welcome.clone();
    bad.max_frame_size = 16384;
    assert!(bad.validate_for(&hello).is_err());
    bad = welcome.clone();
    bad.max_in_flight = 9;
    assert!(bad.validate_for(&hello).is_err());
    bad = welcome;
    bad.generation = 8;
    assert!(bad.validate_for(&hello).is_err());
    hello.min_generation = 3;
    assert_eq!(
        ControlWelcome::negotiate(&hello, 64).unwrap_err().code,
        "unsupported_generation"
    );
    for maximum in [0, 4095, MAX_FRAME_SIZE + 1] {
        let offer = ControlHello {
            max_frame_size: maximum,
            ..Default::default()
        };
        assert_eq!(offer.validate().unwrap_err().code, "invalid_handshake");
    }
}

#[test]
fn hello_keeps_the_unambiguous_zero_prefix() {
    let envelope = Envelope::new(1, "control.hello", &ControlHello::default()).unwrap();
    let mut encoded = Vec::new();
    codec::encode_raw_to_buf(&envelope.frame(0, 0).unwrap(), &mut encoded).unwrap();
    assert_eq!(encoded[0], 0);
    assert!(encoded.len() - 4 <= MAX_HANDSHAKE_FRAME_SIZE as usize);
    assert_eq!(Envelope::decode(&encoded[9..]).unwrap().t, "control.hello");
}

#[test]
fn duplicate_secret_entry_is_rejected_before_dispatch() {
    let change = Value::Map(vec![
        field("change", "rotate".into()),
        field("name", "KEY".into()),
        field("value", "first".into()),
        field("value", "second".into()),
    ]);
    let envelope = Envelope {
        v: 1,
        t: "control.secrets.update".into(),
        p: bytes(&Value::Map(vec![field(
            "changes",
            Value::Array(vec![change]),
        )])),
    };
    assert!(matches!(
        ControlRequest::from_envelope(&envelope),
        Err(WireError::DuplicateKey)
    ));
}

#[test]
fn error_diagnostics_do_not_contain_secret_payloads() {
    let secret = "fixture-sensitive-value";
    let request = ControlRequest::SecretsUpdate {
        changes: vec![SecretChange::Rotate {
            name: "TEST_KEY".into(),
            value: SecretValue(secret.into()),
        }],
    };
    assert!(!format!("{request:?}").contains(secret));
    let envelope = request.envelope(1).unwrap();
    assert!(!format!("{envelope:?}").contains(secret));
    let invalid = bytes(&Value::Map(vec![field(
        "online",
        Value::Text(secret.into()),
    )]));
    assert!(
        !format!(
            "{}",
            wire::decode_record::<CpuTarget>(&invalid).unwrap_err()
        )
        .contains(secret)
    );
}

#[test]
fn legacy_json_spelling_and_optional_discovery_are_preserved() {
    assert_eq!(
        serde_json::to_string(&ControlRequest::MemoryTarget { total_mib: 2048 }).unwrap(),
        r#"{"op":"memory_target","total_mib":2048}"#
    );
    let old: JsonControlResponse = serde_json::from_str(r#"{"ok":true,"capabilities":{"cpu_resize":true,"memory_resize":false,"secrets_update":false}}"#).unwrap();
    assert!(old.control_protocols.is_none());
    let new = JsonControlResponse {
        control_protocols: Some(vec!["json".into(), "cbor".into()]),
        ..old
    };
    let encoded = serde_json::to_value(new).unwrap();
    assert_eq!(encoded["control_protocols"], json!(["json", "cbor"]));
    assert!(encoded.get("memory").is_none());
}

#[test]
fn envelope_requires_a_byte_string_and_preserves_unknown_names() {
    let invalid = bytes(&Value::Map(vec![
        field("v", 1u64.into()),
        field("t", "future.message".into()),
        field("p", Value::Array(vec![0u64.into()])),
    ]));
    assert!(matches!(
        Envelope::decode(&invalid),
        Err(WireError::InvalidRecord)
    ));
    let valid = bytes(&Value::Map(vec![
        field("v", 1u64.into()),
        field("t", "future.message".into()),
        field("p", Value::Bytes(vec![0xff, 0, 0x7f])),
        field("future", "untouched".into()),
    ]));
    let decoded = Envelope::decode(&valid).unwrap();
    assert_eq!(decoded.t, "future.message");
    assert_eq!(decoded.p, vec![0xff, 0, 0x7f]);
}

#[test]
fn generation_two_inventory_and_requests_are_additive() {
    let mut names = CONTROL_GENERATION_TWO_MESSAGES.to_vec();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), CONTROL_GENERATION_TWO_MESSAGES.len());
    assert!(
        names
            .iter()
            .all(|name| control_message_min_generation(name) == Some(2))
    );

    let requests = [
        Envelope::new(
            2,
            "control.checkpoint.create",
            &CheckpointCreate {
                guest_flush: None,
                record_integrity: true,
                checkpoint_id: "full-1".into(),
                intent: CheckpointCaptureIntent::FullSnapshot,
            },
        )
        .unwrap(),
        Envelope::new(
            2,
            "control.disk.checkpoint.create",
            &DiskCheckpointCreate {
                guest_flush: None,
                checkpoint_id: "disk-1".into(),
            },
        )
        .unwrap(),
        Envelope::new(
            2,
            "control.branch.create",
            &BranchCreate {
                guest_flush: None,
                record_integrity: false,
                branch_id: "branch-1".into(),
                child_name: "child".into(),
                memory_cache_dir: "/cache".into(),
            },
        )
        .unwrap(),
        Envelope::new(2, "control.pause", &Pause::default()).unwrap(),
        Envelope::new(2, "control.resume", &Empty {}).unwrap(),
        Envelope::new(2, "control.pause.state", &Empty {}).unwrap(),
        Envelope::new(
            2,
            "control.root-disk.grow",
            &RootDiskGrow {
                size_bytes: u64::MAX,
            },
        )
        .unwrap(),
        Envelope::new(
            2,
            "control.disk.compact",
            &DiskCompact {
                target: microsandbox_types::DiskCompactionTarget::Disk {
                    guest_path: "/data".into(),
                },
                layers: Some(u64::MAX),
                dry_run: true,
            },
        )
        .unwrap(),
        Envelope::new(
            2,
            "control.network-policy.replace",
            &NetworkPolicyReplace {
                policy: probe_policy(),
            },
        )
        .unwrap(),
    ];
    for request in requests {
        assert!(ControlOperation::from_envelope(&request, 2).is_ok());
        let mut generation_one = request;
        generation_one.v = 1;
        assert!(ControlOperation::from_envelope(&generation_one, 1).is_err());
    }
}

#[test]
fn generation_two_rejects_duplicate_nested_compaction_selectors() {
    let target = Value::Map(vec![
        field("kind", "disk".into()),
        field("guest_path", "/first".into()),
        field("guest_path", "/second".into()),
    ]);
    let envelope = Envelope {
        v: 2,
        t: "control.disk.compact".into(),
        p: bytes(&Value::Map(vec![
            field("target", target),
            field("dry_run", true.into()),
        ])),
    };
    assert_eq!(
        ControlOperation::from_envelope(&envelope, 2).unwrap_err(),
        WireError::DuplicateKey
    );
}

#[test]
fn network_policy_replace_payload_bytes_are_pinned() {
    let replace = NetworkPolicyReplace {
        policy: probe_policy(),
    };
    let request = Envelope::new(2, "control.network-policy.replace", &replace).unwrap();
    assert_eq!(
        hex(&request.p),
        "a166706f6c696379a36e64656661756c745f6567726573736464656e796f64656661756c745f696e677265737365616c6c6f776572756c657381a569646972656374696f6e666567726573736b64657374696e6174696f6ea166646f6d61696e6d70726f62652e6578616d706c656970726f746f636f6c73816374637065706f72747381a26573746172741901bb63656e641901bb66616374696f6e65616c6c6f77"
    );
    assert_eq!(
        hex(&request.encode().unwrap()),
        "a36176026174781e636f6e74726f6c2e6e6574776f726b2d706f6c6963792e7265706c616365617058a2a166706f6c696379a36e64656661756c745f6567726573736464656e796f64656661756c745f696e677265737365616c6c6f776572756c657381a569646972656374696f6e666567726573736b64657374696e6174696f6ea166646f6d61696e6d70726f62652e6578616d706c656970726f746f636f6c73816374637065706f72747381a26573746172741901bb63656e641901bb66616374696f6e65616c6c6f77"
    );

    let result = NetworkPolicyResult { revision: 2 };
    let reply = Envelope::new(2, "control.network-policy.result", &result).unwrap();
    assert_eq!(hex(&reply.p), "a1687265766973696f6e02");
    assert_eq!(
        hex(&reply.encode().unwrap()),
        "a36176026174781d636f6e74726f6c2e6e6574776f726b2d706f6c6963792e726573756c7461704ba1687265766973696f6e02"
    );

    // The pinned request payload decodes back to the same operation.
    let ControlOperation::NetworkPolicyReplace(decoded) =
        ControlOperation::from_envelope(&request, 2).unwrap()
    else {
        panic!("expected a network-policy replacement");
    };
    assert_eq!(decoded, replace);
}

#[test]
fn network_policy_replace_rejects_duplicate_known_record_keys() {
    // The assertion is the error code, not the rejection: serde's derive refuses every document
    // below on its own, as `InvalidRecord`. Validating the known record layers first is what makes
    // the refusal precise enough to report `DuplicateKey`, so that is what this test pins.
    let duplicated_policy = Value::Map(vec![
        field("rules", Value::Array(vec![probe_rule()])),
        field("default_egress", "allow".into()),
        field("default_egress", "deny".into()),
    ]);
    let duplicated_rule = Value::Map(vec![
        field("direction", "egress".into()),
        field(
            "destination",
            Value::Map(vec![field("domain", "probe.example".into())]),
        ),
        field("action", "allow".into()),
        field("action", "deny".into()),
    ]);
    let duplicated_destination = Value::Map(vec![
        field("direction", "egress".into()),
        field(
            "destination",
            Value::Map(vec![
                field("domain", "probe.example".into()),
                field("domain", "other.example".into()),
            ]),
        ),
        field("action", "allow".into()),
    ]);
    for policy in [
        duplicated_policy,
        Value::Map(vec![field("rules", Value::Array(vec![duplicated_rule]))]),
        Value::Map(vec![field(
            "rules",
            Value::Array(vec![duplicated_destination]),
        )]),
    ] {
        assert_eq!(
            ControlOperation::from_envelope(&policy_envelope(policy), 2).unwrap_err(),
            WireError::DuplicateKey
        );
    }
}

#[test]
fn network_policy_replace_leaves_unknown_field_values_opaque() {
    // Only the policy map, each rule and each rule's destination are known records. An unknown
    // field may legally hold a map that `validate_record` itself would refuse, such as one with a
    // non-text key, and that must not reject the replacement.
    let extension = Value::Map(vec![(Value::Integer(1.into()), Value::Text("x".into()))]);
    let rule = Value::Map(vec![
        field("direction", "egress".into()),
        field(
            "destination",
            Value::Map(vec![field("domain", "probe.example".into())]),
        ),
        field("action", "allow".into()),
        field("future_rule_field", extension.clone()),
    ]);
    let policy = Value::Map(vec![
        field("rules", Value::Array(vec![rule])),
        field("default_ingress", "allow".into()),
        field("future_policy_field", extension.clone()),
    ]);

    let operation = ControlOperation::from_envelope(&policy_envelope(policy), 2).unwrap();
    let ControlOperation::NetworkPolicyReplace(replace) = operation else {
        panic!("expected a network-policy replacement");
    };
    assert_eq!(replace.policy.rules.len(), 1);
}

#[test]
fn runtime_capabilities_omit_the_policy_flag_when_false() {
    let absent = wire::decode_value(&wire::encode(&RuntimeCapabilities::default()).unwrap())
        .expect("capabilities are a record");
    let Value::Map(fields) = absent else {
        panic!("expected a record")
    };
    assert!(
        fields
            .iter()
            .all(|(key, _)| key.as_text() != Some("network_policy_update")),
        "a false flag must not change the bytes older readers already accept"
    );

    let present = RuntimeCapabilities {
        network_policy_update: true,
        ..Default::default()
    };
    let encoded = wire::decode_value(&wire::encode(&present).unwrap()).unwrap();
    let Value::Map(fields) = encoded else {
        panic!("expected a record")
    };
    assert!(fields.iter().any(|(key, value)| {
        key.as_text() == Some("network_policy_update") && matches!(value, Value::Bool(true))
    }));

    // The frozen generation-one record keeps its four fields only.
    let generation_one = present.generation_one();
    assert_eq!(generation_one, Capabilities::default());
    let frozen = wire::decode_value(&wire::encode(&generation_one).unwrap()).unwrap();
    let Value::Map(fields) = frozen else {
        panic!("expected a record")
    };
    assert!(
        fields
            .iter()
            .all(|(key, _)| key.as_text() != Some("network_policy_update")),
        "the generation-one projection has no policy flag"
    );
}
