use super::*;
use crate::usb::xhci::{model::*, *};
use crate::{
    block::BlockError,
    firmware::{Catalog, Provenance, Resource, Target},
    usb::{
        bluetooth::{Binding, Pipe},
        xhci::{Device, FULL_SPEED},
    },
};
use alloc::{rc::Rc, vec};
use core::cell::Cell;
use core::cell::RefCell;
use sha2::{Digest, Sha256};

// Original synthetic bytes exercise structure/protocol only. They contain
// no vendor image/signature and do not prove real secure-ROM authentication.
pub(crate) fn image() -> Vec<u8> {
    let mut bytes = vec![0; 644];
    bytes[..4].copy_from_slice(&6u32.to_le_bytes());
    for (at, value) in [
        (4, 161u32),
        (16, 0x8086),
        (24, 165),
        (28, 64),
        (32, 64),
        (36, 1),
    ] {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    bytes[128..384].fill(0x5a);
    bytes[384..388].copy_from_slice(&[1, 0, 1, 0]);
    bytes[388..644].fill(0x6b);
    bytes.extend_from_slice(&[0x0e, 0xfc, 7, 0, 0, 0x20, 0, 9, 30, 26, 0, 0xfc, 3, 0, 0, 0]);
    bytes
}
fn version(operational: bool) -> Vec<u8> {
    vec![
        0,
        0x37,
        0x14,
        1,
        if operational { 0x23 } else { 6 },
        if operational { 4 } else { 3 },
        if operational { 9 } else { 1 },
        30,
        26,
        0,
    ]
}
fn boot_parameters() -> Vec<u8> {
    let mut p = vec![0; 23];
    p[4] = 1;
    p[6] = 1;
    p[12..18].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
    p[18..21].copy_from_slice(&[1, 1, 25]);
    p
}
fn complete(opcode: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0x0e, (3 + payload.len()) as u8, 1];
    p.extend_from_slice(&opcode.to_le_bytes());
    p.extend_from_slice(payload);
    p
}
fn command_bytes(opcode: u16, params: &[u8]) -> Vec<u8> {
    let mut p = opcode.to_le_bytes().to_vec();
    p.push(params.len() as u8);
    p.extend_from_slice(params);
    p
}
pub(crate) struct Step {
    command: Vec<u8>,
    bulk: bool,
    events: Vec<(Pipe, Vec<u8>)>,
}
pub(crate) struct Script {
    pub steps: VecDeque<Step>,
}
impl Script {
    pub(crate) fn command(&mut self, bulk: bool, bytes: &[u8]) -> Vec<(Pipe, Vec<u8>)> {
        let step = self.steps.pop_front().expect("unexpected USB command");
        assert_eq!(bulk, step.bulk, "wrong USB command endpoint");
        assert_eq!(bytes, step.command, "wrong command bytes/sequence");
        step.events
    }
}
pub(crate) fn fixture() -> (Device, Catalog, Script) {
    let mut device = Device {
        id: crate::usb::xhci::SlotId::fixture(1),
        vendor_ethernet_revision: None,
        vendor_ethernet_tcr: None,
        slot: 1,
        speed: FULL_SPEED,
        location: "Intel model".into(),
        descriptor: [
            18, 1, 0, 2, 0xe0, 1, 1, 64, 0x87, 0x80, 0x29, 0, 0, 1, 0, 0, 0, 1,
        ],
        configurations: Vec::new(),
        configuration: vec![
            9, 2, 39, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 3, 0xe0, 1, 1, 0, 7, 5, 0x81, 3, 16, 0, 1,
            7, 5, 0x82, 2, 64, 0, 0, 7, 5, 0x02, 2, 64, 0, 0,
        ],
        manufacturer: None,
        product: None,
        serial: None,
        language: None,
    };
    device.configurations = vec![device.configuration.clone()];
    let sfi = image();
    let mut steps = VecDeque::new();
    let mut add = |opcode, params: &[u8], bulk, pipe, payload: &[u8]| {
        steps.push_back(Step {
            command: command_bytes(opcode, params),
            bulk,
            events: vec![(pipe, complete(opcode, payload))],
        })
    };
    add(READ_VERSION, &[0xff], false, Pipe::Event, &version(false));
    add(
        READ_BOOT_PARAMS,
        &[],
        false,
        Pipe::Event,
        &boot_parameters(),
    );
    // Exact pinned RSA wire layout, independent of Sfi::sections/parser.
    for (kind, bytes) in [
        (0, &sfi[..128]),
        (3, &sfi[128..380]),
        (3, &sfi[380..384]),
        (2, &sfi[388..640]),
        (2, &sfi[640..644]),
        (1, &sfi[644..]),
    ] {
        let mut params = vec![kind];
        params.extend_from_slice(bytes);
        add(SECURE_SEND, &params, true, Pipe::Acl, &[0]);
    }
    // Coalesced final command completion + secure result on bulk IN.
    steps.back_mut().unwrap().events[0]
        .1
        .extend_from_slice(&[0xff, 5, 6, 0, 9, 0xfc, 0]);
    // Boot event split across bulk USB completions.
    steps.push_back(Step {
        command: command_bytes(INTEL_RESET, &[0, 1, 0, 1, 0, 0, 0x20, 0]),
        bulk: false,
        events: vec![
            (Pipe::Acl, vec![0xff, 7]),
            (Pipe::Acl, vec![2, 0, 1, 0, 0, 0, 0]),
        ],
    });
    let mut add = |opcode, params: &[u8], payload: &[u8]| {
        steps.push_back(Step {
            command: command_bytes(opcode, params),
            bulk: false,
            events: vec![(Pipe::Event, complete(opcode, payload))],
        })
    };
    add(READ_VERSION, &[], &version(true));
    add(READ_BD_ADDR, &[], &[0, 1, 2, 3, 4, 5, 6]);
    add(WRITE_DDC, &[3, 1, 2, 0xaa], &[0]);
    add(READ_VERSION, &[], &version(true));
    (device, catalog(sfi, vec![3, 1, 2, 0xaa]), Script { steps })
}
fn catalog(sfi: Vec<u8>, ddc: Vec<u8>) -> Catalog {
    let target = Target {
        driver: "intel-bluetooth-usb-rsa",
        hardware: "usb:8087:0029:0100",
        revision: "37:14:01:03:dev-0001:otp-00-00-00:key-00-00:locks-00-00-00:min-01-01-19:loader-01-1e-1a-00:unlock-00",
        board: None,
    };
    let provenance = Provenance {
        source: "Stela synthetic protocol model",
        revision: "1",
        member: "synthetic/intel-model",
        license: "MIT",
    };
    Catalog::from_handoff(vec![
        Resource {
            name: "intel/ibt-20-1-3.sfi",
            target,
            provenance,
            expected_length: sfi.len(),
            expected_sha256: Sha256::digest(&sfi).into(),
            bytes: sfi,
        },
        Resource {
            name: "intel/ibt-20-1-3.ddc",
            target,
            provenance,
            expected_length: ddc.len(),
            expected_sha256: Sha256::digest(&ddc).into(),
            bytes: ddc,
        },
    ])
    .unwrap()
}
struct Model {
    script: Script,
    event: VecDeque<Vec<u8>>,
    bulk: VecDeque<Vec<u8>>,
    time: Cell<u64>,
    closed: Rc<Cell<usize>>,
    quiesced: usize,
    fail_reset: bool,
    fail_quiesce: bool,
    fail_close: bool,
    submitted: usize,
}
impl Model {
    fn dispatch(&mut self, bulk: bool, packet: &[u8]) -> core::result::Result<(), BlockError> {
        self.submitted += 1;
        if self.fail_reset && packet[..2] == INTEL_RESET.to_le_bytes() {
            return Err(BlockError::Unsupported("disconnected; rebind required"));
        }
        for (pipe, event) in self.script.command(bulk, packet) {
            match pipe {
                Pipe::Event => &mut self.event,
                Pipe::Acl => &mut self.bulk,
            }
            .push_back(event);
        }
        Ok(())
    }
}
impl Io for Model {
    fn validate(&self) -> core::result::Result<(), BlockError> {
        Ok(()) // This in-memory model has no physical device-generation owner.
    }
    fn control(&mut self, setup: [u8; 8], p: &[u8]) -> core::result::Result<(), BlockError> {
        assert_eq!(setup[..6], [0x20, 0, 0, 0, 0, 0]);
        self.dispatch(false, p)
    }
    fn receive(&mut self, pipe: Pipe) -> core::result::Result<Option<Vec<u8>>, BlockError> {
        Ok(match pipe {
            Pipe::Event => &mut self.event,
            Pipe::Acl => &mut self.bulk,
        }
        .pop_front())
    }
    fn write_acl(&mut self, p: &[u8]) -> core::result::Result<(), BlockError> {
        self.dispatch(true, p)
    }
    fn quiesce_bulk(&mut self) -> core::result::Result<(), BlockError> {
        self.quiesced += 1;
        if self.fail_quiesce {
            Err(BlockError::Timeout)
        } else {
            Ok(())
        }
    }
    fn close(&mut self) -> core::result::Result<(), BlockError> {
        self.closed.set(self.closed.get() + 1);
        if self.fail_close {
            Err(BlockError::Timeout)
        } else {
            Ok(())
        }
    }
    fn now_us(&self) -> u64 {
        let now = self.time.get();
        self.time.set(now + 100_000);
        now
    }
}
fn transport(device: Device, script: Script) -> Hci<Model> {
    let interface = crate::usb::descriptor::interfaces(&device.configuration).remove(0);
    let binding = Binding::new(&device, &interface).unwrap();
    Hci::from_io(
        binding,
        Model {
            script,
            event: VecDeque::new(),
            bulk: VecDeque::new(),
            time: Cell::new(0),
            closed: Rc::new(Cell::new(0)),
            quiesced: 0,
            fail_reset: false,
            fail_quiesce: false,
            fail_close: false,
            submitted: 0,
        },
    )
}
#[test]
fn secure_boot_sequence_uses_real_completions_and_returns_catalog_provenance() {
    let (device, catalog, script) = fixture();
    let mut hci = transport(device, script);
    let report = initialize(&mut hci, &catalog).unwrap();
    assert!(report.after.is_operational());
    assert_eq!(report.after.build(), Some([9, 30, 26]));
    let FirmwareEvidence::Uploaded {
        firmware,
        configuration,
    } = report.evidence
    else {
        panic!("expected upload evidence")
    };
    assert_eq!(firmware.sha256(), Sha256::digest(image())[..]);
    assert_eq!(
        configuration.provenance().source,
        "Stela synthetic protocol model"
    );
    assert!(hci.test_io().script.steps.is_empty());
    assert_eq!(hci.test_io().quiesced, 2);
    assert_eq!(hci.state(), State::Open);
    assert!(!hci.test_intel_mode());
    assert_eq!(
        hci.firmware_status(),
        crate::usb::bluetooth::FirmwareStatus::Unverified
    );
}
#[test]
fn every_sfi_truncation_and_malformed_ddc_fails_before_upload() {
    let valid = image();
    for end in 0..valid.len() {
        assert!(
            firmware::Sfi::parse(&valid[..end], [1, 1, 25]).is_err(),
            "prefix {end}"
        );
    }
    for bytes in [vec![], vec![0], vec![1, 0], vec![3, 1, 2], vec![255; 256]] {
        assert!(firmware::ddc(&bytes).is_err());
    }
    for corrupt in 0..5 {
        let (device, _, script) = fixture();
        let mut bytes = image();
        let mut ddc = vec![3, 1, 2, 0xaa];
        match corrupt {
            0 => bytes[8] = 1,
            1 => bytes[128..384].fill(0),
            2 => bytes[646] = 255,
            3 => bytes.push(0),
            _ => ddc.pop().map(|_| ()).unwrap(),
        };
        let catalog = catalog(bytes, ddc);
        let mut hci = transport(device, script);
        assert!(matches!(
            initialize(&mut hci, &catalog),
            Err(Error::FirmwareFormat(_))
        ));
        assert_eq!(hci.test_io().submitted, 2);
        assert_eq!(hci.state(), State::Closed);
    }
}
/// The secure send result is judged by its result byte alone, as Linux
/// `btintel_secure_send_result` judges it: controllers differ in the opcode
/// and status bytes that follow.
#[test]
fn a_secure_send_result_is_accepted_whatever_opcode_and_status_it_names() {
    for byte in [10, 11, 12] {
        let (device, catalog, mut script) = fixture();
        script.steps[7].events[0].1[byte] ^= 1;
        let mut hci = transport(device, script);
        assert!(initialize(&mut hci, &catalog).is_ok(), "byte {byte}");
    }
}
#[test]
fn command_vendor_reset_identity_and_address_failures_never_report_ready() {
    for case in 0..16 {
        let (device, catalog, mut script) = fixture();
        match case {
            0 => script.steps[2].events.clear(), // USB delivery without HCI CC
            1 => script.steps[2].events[0].1[3] ^= 1,
            2 => script.steps[2].events[0].1[5] = 0x0c,
            3 => script.steps[7].events[0].1[9] = 1, // secure-result rejection
            4 => script.steps[7].events[0].1.truncate(6), // final CC only
            5 => script.steps[8].events.clear(),     // reset delivery without boot
            6 => script.steps[8].events = vec![(Pipe::Acl, complete(INTEL_RESET, &[0]))],
            7 => script.steps[9].events[0].1[7] ^= 1, // hardware variant
            8 => script.steps[9].events[0].1[11] ^= 1, // build
            9 => script.steps[10].events[0].1[6] ^= 1, // address
            10 => script.steps[2].events[0].1[2] = 0, // zero credits
            11 => script.steps[7].events[0].1[9] = 0xff, // secure-result rejection, another code
            12 => script.steps[8].events[1].1[6] = 1, // boot DDC error
            13 => script.steps[2].events[0].1 = vec![0x0f, 4, 0, 1, 9, 0xfc], // Status is not Complete
            14 => {
                let duplicate = script.steps[2].events[0].1.clone();
                script.steps[2].events[0].1.extend(duplicate);
            }
            _ => {
                let duplicate = script.steps[12].events[0].1.clone();
                script.steps[12].events[0].1.extend(duplicate);
            }
        }
        let mut hci = transport(device, script);
        assert!(initialize(&mut hci, &catalog).is_err(), "case {case}");
        assert_ne!(hci.state(), State::Open);
        assert_eq!(
            hci.firmware_status(),
            crate::usb::bluetooth::FirmwareStatus::Unverified
        );
    }
}
#[test]
fn usb_disconnect_quiescence_and_exact_target_errors_close_transport() {
    for case in 0..4 {
        let (device, catalog, script) = fixture();
        let mut hci = transport(device, script);
        hci.test_io().fail_reset = case == 0;
        hci.test_io().fail_quiesce = case == 1;
        let empty = Catalog::from_handoff(vec![]).unwrap();
        if case == 3 {
            hci.test_device().descriptor[12] ^= 1;
        }
        let provider: &dyn Provider = if case == 2 { &empty } else { &catalog };
        assert!(initialize(&mut hci, provider).is_err());
        assert_ne!(hci.state(), State::Open);
        assert_eq!(hci.test_io().closed.get(), 1);
    }
}
fn tlv_version(operational: bool, engine: u8) -> Vec<u8> {
    tlv_version_variant(operational, engine, 0x18)
}
pub(crate) fn tlv_version_variant(operational: bool, engine: u8, variant: u8) -> Vec<u8> {
    let mut reply = vec![0];
    let mut add = |kind: u8, value: &[u8]| {
        reply.extend_from_slice(&[kind, value.len() as u8]);
        reply.extend_from_slice(value);
    };
    for (kind, value) in [
        (0x10, 0x410u32),
        (0x11, 0x410),
        (0x12, (u32::from(variant) << 16) | 0x3700),
        (0x13, (u32::from(variant) << 16) | 0x3700),
    ] {
        add(kind, &value.to_le_bytes());
    }
    add(0x16, &1u16.to_le_bytes());
    add(0x1c, &[if operational { 3 } else { 1 }]);
    add(0x1d, &[30, 26]);
    add(0x1f, &if operational { 9u32 } else { 1 }.to_le_bytes());
    if !operational {
        for (kind, value) in [
            (0x28, 1),
            (0x29, 0),
            (0x2a, 0),
            (0x2b, 0),
            (0x2c, 0),
            (0x2e, 0),
            (0x2f, engine),
        ] {
            add(kind, &[value]);
        }
        add(0x2d, &[1, 1, 25]);
        add(0x30, &[1, 2, 3, 4, 5, 6]);
    }
    add(0x90, &[0xa5, 0x5a]);
    reply
}
pub(crate) fn combined_image() -> Vec<u8> {
    let legacy = image();
    let mut bytes = legacy[..644].to_vec();
    let mut ecdsa = vec![0; 320];
    for (at, value) in [
        (0, 6u32),
        (4, 80),
        (8, 0x20000),
        (16, 0x8086),
        (24, 84),
        (28, 24),
        (32, 12),
        (36, 12),
    ] {
        ecdsa[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    ecdsa[128..224].fill(0x77);
    ecdsa[224..320].fill(0x88);
    bytes.extend_from_slice(&ecdsa);
    bytes.extend_from_slice(&legacy[644..]);
    bytes
}
pub(crate) fn hybrid_image() -> Vec<u8> {
    let legacy = image();
    let mut bytes = vec![0; 2116];
    // Synthetic opaque CSS; only its source discriminator is known.
    // No vendor signature, complete hybrid CSS field schema or crypto proof.
    bytes[..128].copy_from_slice(&legacy[..128]);
    bytes[8..12].copy_from_slice(&0x0006_9700u32.to_le_bytes());
    bytes[128..224].fill(0x31);
    bytes[224..320].fill(0x42);
    bytes[320..372].fill(0x53);
    bytes[372..2116].fill(0x64);
    bytes.extend_from_slice(&legacy[644..]);
    bytes
}
pub(crate) fn hybrid_fragments(image: &[u8]) -> Vec<(u8, &[u8])> {
    // Independent pinned source wire ranges, including all seven
    // 252-byte-max LMS signature fragments. No production parser/constants.
    vec![
        (0, &image[..128]),
        (3, &image[128..224]),
        (2, &image[224..320]),
        (5, &image[320..372]),
        (4, &image[372..624]),
        (4, &image[624..876]),
        (4, &image[876..1128]),
        (4, &image[1128..1380]),
        (4, &image[1380..1632]),
        (4, &image[1632..1884]),
        (4, &image[1884..2116]),
        (1, &image[2116..]),
    ]
}
fn tlv_fixture(engine: u8) -> (Device, Catalog, Script) {
    tlv_fixture_variant(engine, 0x18)
}
fn tlv_fixture_variant(engine: u8, variant: u8) -> (Device, Catalog, Script) {
    let (mut device, _, _) = fixture();
    device.descriptor[10] = 0x32;
    let before = tlv_version_variant(false, engine, variant);
    let after = tlv_version_variant(true, engine, variant);
    let identity = TlvIdentity::parse(&device, &before).unwrap();
    assert_eq!(identity.filename("sfi"), "intel/ibt-0041-0041.sfi");
    let bytes = combined_image();
    let mut steps = VecDeque::new();
    steps.push_back(Step {
        command: command_bytes(READ_VERSION, &[0xff]),
        bulk: false,
        events: vec![(Pipe::Event, complete(READ_VERSION, &before))],
    });
    let sections: Vec<(u8, &[u8])> = if engine == 0 {
        vec![
            (0, &bytes[..128]),
            (3, &bytes[128..380]),
            (3, &bytes[380..384]),
            (2, &bytes[388..640]),
            (2, &bytes[640..644]),
            (1, &bytes[964..]),
        ]
    } else {
        vec![
            (0, &bytes[644..772]),
            (3, &bytes[772..868]),
            (2, &bytes[868..964]),
            (1, &bytes[964..]),
        ]
    };
    for (kind, section) in sections {
        let mut p = vec![kind];
        p.extend_from_slice(section);
        steps.push_back(Step {
            command: command_bytes(SECURE_SEND, &p),
            bulk: true,
            events: vec![(Pipe::Acl, complete(SECURE_SEND, &[0]))],
        });
    }
    steps.back_mut().unwrap().events[0]
        .1
        .extend_from_slice(&[0xff, 5, 6, 0, 9, 0xfc, 0]);
    steps.push_back(Step {
        command: command_bytes(INTEL_RESET, &[0, 1, 0, 1, 0, 0, 0x20, 0]),
        bulk: false,
        events: vec![(Pipe::Acl, vec![0xff, 7, 2, 0, 1, 0, 0, 0, 0])],
    });
    for (opcode, parameters, payload) in [
        (READ_VERSION, vec![0xff], after.clone()),
        (READ_BD_ADDR, vec![], vec![0, 1, 2, 3, 4, 5, 6]),
        (WRITE_DDC, vec![3, 1, 2, 0xaa], vec![0]),
        (READ_VERSION, vec![0xff], after),
    ] {
        if opcode == READ_BD_ADDR && matches!(variant, 0x1c | 0x1d) {
            steps.push_back(Step {
                command: command_bytes(0xfc0a, &[0, 0]),
                bulk: false,
                events: vec![(Pipe::Event, complete(0xfc0a, &[0]))],
            });
        }
        steps.push_back(Step {
            command: command_bytes(opcode, &parameters),
            bulk: false,
            events: vec![(Pipe::Event, complete(opcode, &payload))],
        });
    }
    let hardware = identity.hardware_label();
    let revision = identity.revision_label();
    let target = identity.target(&hardware, &revision);
    let provenance = Provenance {
        source: "Stela synthetic TLV model",
        revision: "1",
        member: "synthetic/tlv",
        license: "MIT",
    };
    let ddc = vec![3, 1, 2, 0xaa];
    let catalog = Catalog::from_handoff(vec![
        Resource {
            name: "intel/ibt-0041-0041.sfi",
            target,
            provenance,
            expected_length: bytes.len(),
            expected_sha256: Sha256::digest(&bytes).into(),
            bytes,
        },
        Resource {
            name: "intel/ibt-0041-0041.ddc",
            target,
            provenance,
            expected_length: ddc.len(),
            expected_sha256: Sha256::digest(&ddc).into(),
            bytes: ddc,
        },
    ])
    .unwrap();
    (device, catalog, Script { steps })
}
#[test]
fn tlv_controllers_load_the_identified_engine_files() {
    for engine in [0, 1] {
        let (device, catalog, script) = tlv_fixture(engine);
        let mut hci = transport(device, script);
        let report = initialize(&mut hci, &catalog).unwrap();
        assert!(matches!(report.after,ControllerIdentity::Tlv(ref i) if i.image_type==3));
        assert!(matches!(report.evidence, FirmwareEvidence::Uploaded { .. }));
        assert!(report.boot_notification.is_some());
        assert_eq!(report.address, [1, 2, 3, 4, 5, 6]);
        assert!(hci.test_io().script.steps.is_empty());
        assert_eq!(hci.test_io().quiesced, 2);
        assert_eq!(hci.state(), State::Open);
    }
}
#[test]
fn already_running_legacy_tlv_and_legacy_fallback_have_unknown_provenance() {
    for kind in 0..3 {
        let (mut device, _, _) = fixture();
        if kind == 1 {
            device.descriptor[10] = 0x32;
        }
        let initial = if kind == 1 {
            tlv_version(true, 1)
        } else if kind == 2 {
            vec![0, 0x12, 4, 0, 0x37, 0x14, 0]
        } else {
            version(true)
        };
        let final_version = if kind == 1 {
            tlv_version(true, 1)
        } else {
            version(true)
        };
        let mut steps = VecDeque::from([Step {
            command: command_bytes(READ_VERSION, &[0xff]),
            bulk: false,
            events: vec![(Pipe::Event, complete(READ_VERSION, &initial))],
        }]);
        if kind == 2 {
            steps.push_back(Step {
                command: command_bytes(READ_VERSION, &[]),
                bulk: false,
                events: vec![(Pipe::Event, complete(READ_VERSION, &version(true)))],
            });
        }
        steps.push_back(Step {
            command: command_bytes(READ_BD_ADDR, &[]),
            bulk: false,
            events: vec![(Pipe::Event, complete(READ_BD_ADDR, &[0, 1, 2, 3, 4, 5, 6]))],
        });
        steps.push_back(Step {
            command: command_bytes(READ_VERSION, if kind == 1 { &[0xff] } else { &[] }),
            bulk: false,
            events: vec![(Pipe::Event, complete(READ_VERSION, &final_version))],
        });
        let mut hci = transport(device, Script { steps });
        let empty = Catalog::from_handoff(vec![]).unwrap();
        let input = DsbrInput::Present {
            revision: 7,
            raw: 0xb1,
        };
        let report =
            initialize_with_platform(&mut hci, &empty, PlatformInputs { dsbr: input }).unwrap();
        assert_eq!(
            report.dsbr,
            DsbrReport {
                input,
                applied: None
            }
        );
        assert!(matches!(report.evidence, FirmwareEvidence::RunningUnknown));
        assert!(report.boot_notification.is_none());
        assert!(report.after.is_operational());
        assert_eq!(hci.test_io().quiesced, 0);
        assert!(hci.test_io().script.steps.is_empty());
        assert_eq!(
            hci.firmware_status(),
            crate::usb::bluetooth::FirmwareStatus::Unverified
        );
    }
}
#[test]
fn tlv_identity_canonicalization_and_malformed_fields_fail_closed() {
    let (mut device, _, _) = fixture();
    device.descriptor[10] = 0x32;
    let valid = tlv_version(false, 1);
    let identity = TlvIdentity::parse(&device, &valid).unwrap();
    let mut chunks = Vec::new();
    let mut at = 1;
    while at < valid.len() {
        let end = at + 2 + usize::from(valid[at + 1]);
        chunks.push(valid[at..end].to_vec());
        at = end;
    }
    let mut reversed = vec![0];
    for chunk in chunks.iter().rev() {
        reversed.extend_from_slice(chunk);
    }
    assert_eq!(
        TlvIdentity::parse(&device, &reversed)
            .unwrap()
            .revision_label(),
        identity.revision_label()
    );
    assert_eq!(identity.revision_label().len(), 78);
    assert_eq!(identity.canonical_tlvs().len() + 1, valid.len());
    let mut extended = valid.clone();
    extended.extend_from_slice(&[0x91, 100]);
    extended.extend_from_slice(&[0xa5; 100]);
    let extended = TlvIdentity::parse(&device, &extended).unwrap();
    assert_eq!(extended.revision_label().len(), 78);
    assert_ne!(extended.revision_label(), identity.revision_label());
    assert_eq!(
        extended.canonical_tlvs().len(),
        identity.canonical_tlvs().len() + 102
    );
    for chunk in &chunks {
        let mut duplicate = valid.clone();
        duplicate.extend_from_slice(chunk);
        assert!(TlvIdentity::parse(&device, &duplicate).is_err());
    }
    for index in 0..chunks.len() {
        let mut missing = vec![0];
        for (i, c) in chunks.iter().enumerate() {
            if i != index {
                missing.extend_from_slice(c);
            }
        }
        if matches!(chunks[index][0],0x10..=0x13|0x16|0x1c|0x28|0x2a..=0x30) {
            assert!(
                TlvIdentity::parse(&device, &missing).is_err(),
                "missing {:x}",
                chunks[index][0]
            );
        }
        let mut malformed = chunks.clone();
        malformed[index][1] = 255;
        let mut p = vec![0];
        for c in malformed {
            p.extend(c);
        }
        assert!(TlvIdentity::parse(&device, &p).is_err());
    }
    for at in [644, 648, 652, 660, 668, 672, 676, 680] {
        let mut bytes = combined_image();
        bytes[at] ^= 1;
        assert!(firmware::Sfi::parse_tlv(&bytes, [0; 3], 1, 0x18).is_err());
    }
    assert!(firmware::Sfi::parse_tlv(&combined_image(), [0; 3], 2, 0x20).is_err());
}
#[test]
fn missing_sfi_still_records_exact_ddc_companion_without_upload() {
    use alloc::string::String;
    use core::cell::RefCell;
    struct Recording<'a> {
        catalog: &'a Catalog,
        calls: RefCell<Vec<(String, String, String, String)>>,
    }
    impl Provider for Recording<'_> {
        fn load(
            &self,
            r: Requirement<'_>,
        ) -> core::result::Result<Image<'_>, crate::firmware::Error> {
            self.calls.borrow_mut().push((
                r.name.into(),
                r.target.driver.into(),
                r.target.hardware.into(),
                r.target.revision.into(),
            ));
            self.catalog.load(r)
        }
    }
    for modern in [false, true] {
        let (device, _, script) = if modern { tlv_fixture(1) } else { fixture() };
        let mut hci = transport(device, script);
        let empty = Catalog::from_handoff(vec![]).unwrap();
        let provider = Recording {
            catalog: &empty,
            calls: RefCell::new(Vec::new()),
        };
        let error = initialize(&mut hci, &provider).unwrap_err();
        let calls = provider.calls.borrow();
        assert_eq!(calls.len(), 2);
        let stem = if modern {
            "intel/ibt-0041-0041"
        } else {
            "intel/ibt-20-1-3"
        };
        assert_eq!(calls[0].0, format!("{stem}.sfi"));
        assert_eq!(calls[1].0, format!("{stem}.ddc"));
        assert_eq!(
            calls[0].1,
            if modern {
                "intel-bluetooth-usb-tlv"
            } else {
                "intel-bluetooth-usb-rsa"
            }
        );
        assert_eq!(
            calls[0].2,
            if modern {
                "usb:8087:0032:0100"
            } else {
                "usb:8087:0029:0100"
            }
        );
        assert_eq!(
            (&calls[0].1, &calls[0].2, &calls[0].3),
            (&calls[1].1, &calls[1].2, &calls[1].3)
        );
        assert!(
            matches!(error,Error::Resource(ref e) if e.name==calls[0].0 && matches!(e.kind,crate::firmware::ErrorKind::Missing))
        );
        assert_eq!(hci.test_io().submitted, if modern { 1 } else { 2 });
        assert_eq!(hci.state(), State::Closed);
    }
}
#[test]
fn dsbr_uploaded_variants_preserve_override_and_distinguish_documented_defaults() {
    for variant in [0x1c, 0x1d] {
        for input in [
            DsbrInput::Absent,
            DsbrInput::Unavailable,
            DsbrInput::Present {
                revision: 1,
                raw: 0xb1,
            },
            DsbrInput::Present {
                revision: 2,
                raw: 0xf1,
            },
            DsbrInput::Present {
                revision: 7,
                raw: 0xffff_ffff,
            },
        ] {
            let (device, catalog, mut script) = tlv_fixture_variant(1, variant);
            let step = script
                .steps
                .iter_mut()
                .find(|s| s.command[..2] == [0x0a, 0xfc])
                .unwrap();
            step.command = command_bytes(0xfc0a, &input.parameters());
            let mut hci = transport(device, script);
            let report =
                initialize_with_platform(&mut hci, &catalog, PlatformInputs { dsbr: input })
                    .unwrap();
            assert_eq!(
                report.dsbr,
                DsbrReport {
                    input,
                    applied: Some(input.parameters())
                }
            );
            assert!(hci.test_io().script.steps.is_empty());
            assert_eq!(hci.state(), State::Open);
        }
    }
    let input = DsbrInput::Present {
        revision: 3,
        raw: 0xf1,
    };
    let (device, catalog, script) = tlv_fixture(1);
    let mut hci = transport(device, script);
    let report =
        initialize_with_platform(&mut hci, &catalog, PlatformInputs { dsbr: input }).unwrap();
    assert_eq!(
        report.dsbr,
        DsbrReport {
            input,
            applied: None
        }
    );
}
#[test]
fn dsbr_requires_real_matching_successful_command_completion() {
    for case in 0..4 {
        let (device, catalog, mut script) = tlv_fixture_variant(1, 0x1c);
        let step = script
            .steps
            .iter_mut()
            .find(|s| s.command[..2] == [0x0a, 0xfc])
            .unwrap();
        match case {
            0 => step.events.clear(),
            1 => step.events[0].1[5] = 0x0c,
            2 => step.events[0].1[3] ^= 1,
            _ => step.events[0].1 = complete(0xfc0a, &[0, 0]),
        }
        let mut hci = transport(device, script);
        assert!(
            initialize_with_platform(
                &mut hci,
                &catalog,
                PlatformInputs {
                    dsbr: DsbrInput::Absent
                }
            )
            .is_err()
        );
        assert_eq!(hci.state(), State::Closed);
    }
}

mod native_tests {
    use super::*;
    use crate::usb::bluetooth::{FirmwareStatus, InitializationError, InitializationReport};
    use alloc::string::String;
    use core::cell::RefCell;
    struct Recording<'a> {
        catalog: &'a Catalog,
        calls: RefCell<Vec<String>>,
    }
    impl Provider for Recording<'_> {
        fn load(
            &self,
            r: Requirement<'_>,
        ) -> core::result::Result<Image<'_>, crate::firmware::Error> {
            self.calls.borrow_mut().push(r.name.into());
            self.catalog.load(r)
        }
    }
    #[test]
    fn native_owned_upload_evidence_outlives_provider_and_never_reinitializes() {
        for path in 0..3 {
            let (device, _, script) = match path {
                0 => fixture(),
                1 => tlv_fixture(1),
                _ => super::iml_tests::fixture_iml(0x1e, 1, true),
            };
            let mut hci = transport(device, script);
            assert!(hci.initialization().is_none());
            let retained;
            {
                let (_, catalog, _) = match path {
                    0 => fixture(),
                    1 => tlv_fixture(1),
                    _ => super::iml_tests::fixture_iml(0x1e, 1, true),
                };
                retained = hci
                    .initialize_with_provider(&catalog, PlatformInputs::default())
                    .unwrap();
            }
            // This borrow of the result crosses the Catalog's destruction:
            // the public method's returned lifetime belongs only to Hci.
            let InitializationReport::Intel(report) = retained else {
                panic!("expected Intel report")
            };
            assert!(report.after.is_operational());
            match (&report.evidence, path) {
                (
                    OwnedFirmwareEvidence::Uploaded {
                        firmware,
                        configuration,
                    },
                    0 | 1,
                ) => {
                    assert!(firmware.name.ends_with(".sfi"));
                    assert!(configuration.name.ends_with(".ddc"));
                    assert_eq!(firmware.target_revision, configuration.target_revision);
                    assert!(firmware.source.starts_with("Stela synthetic"));
                }
                (
                    OwnedFirmwareEvidence::MultiStage {
                        firmware,
                        configuration,
                    },
                    2,
                ) => {
                    assert_eq!(firmware.len(), 2);
                    assert_eq!(firmware[0].name, "intel/ibt-0190-0041-iml.sfi");
                    assert_eq!(firmware[1].target_revision, configuration.target_revision);
                    assert_eq!(report.stages.len(), 2);
                }
                _ => panic!("exact uploaded evidence required"),
            }
            let submitted = hci.test_io().submitted;
            let empty = Catalog::from_handoff(vec![]).unwrap();
            let provider = Recording {
                catalog: &empty,
                calls: RefCell::new(Vec::new()),
            };
            assert!(
                hci.initialize_with_provider(
                    &provider,
                    PlatformInputs {
                        dsbr: DsbrInput::Present {
                            revision: 9,
                            raw: 0xb1
                        }
                    }
                )
                .is_ok()
            );
            assert!(provider.calls.borrow().is_empty());
            assert_eq!(hci.test_io().submitted, submitted);
            assert_eq!(hci.firmware_status(), FirmwareStatus::Unverified);
            // The kept observation does not reopen a later closed HCI.
            hci.close().unwrap();
            assert!(hci.initialization().unwrap().is_ok());
            assert!(
                hci.submit_command(&command_bytes(READ_VERSION, &[0xff]))
                    .is_err()
            );
            assert_eq!(hci.test_io().submitted, submitted);
        }
    }
    #[test]
    fn native_running_unknown_has_no_uploaded_provenance_and_no_resource_requests() {
        for modern in [false, true] {
            let (mut device, _, _) = fixture();
            if modern {
                device.descriptor[10] = 0x32;
            }
            let version = if modern {
                tlv_version(true, 1)
            } else {
                version(true)
            };
            let mut steps = VecDeque::new();
            super::iml_tests::add_command(&mut steps, READ_VERSION, &[0xff], &version);
            super::iml_tests::add_command(&mut steps, READ_BD_ADDR, &[], &[0, 1, 2, 3, 4, 5, 6]);
            super::iml_tests::add_command(
                &mut steps,
                READ_VERSION,
                if modern { &[0xff] } else { &[] },
                &version,
            );
            let mut hci = transport(device, Script { steps });
            {
                let empty = Catalog::from_handoff(vec![]).unwrap();
                let provider = Recording {
                    catalog: &empty,
                    calls: RefCell::new(Vec::new()),
                };
                let InitializationReport::Intel(report) = hci
                    .initialize_with_provider(&provider, PlatformInputs::default())
                    .unwrap()
                else {
                    panic!("expected Intel report")
                };
                assert!(matches!(
                    report.evidence,
                    OwnedFirmwareEvidence::RunningUnknown
                ));
                assert!(report.boot_notification.is_none());
                assert!(report.stages.is_empty());
                assert!(provider.calls.borrow().is_empty());
            }
            let InitializationReport::Intel(report) = hci.initialization().unwrap().unwrap() else {
                panic!("expected Intel report")
            };
            assert!(report.after.is_operational());
            assert_eq!(hci.firmware_status(), FirmwareStatus::Unverified);
            assert!(hci.test_io().script.steps.is_empty());
        }
    }
    #[test]
    fn native_missing_resources_remain_exact_typed_and_cannot_retry_closed_candidate() {
        let (device, catalog, script) = fixture();
        let mut hci = transport(device, script);
        {
            let empty = Catalog::from_handoff(vec![]).unwrap();
            let provider = Recording {
                catalog: &empty,
                calls: RefCell::new(Vec::new()),
            };
            let error = hci
                .initialize_with_provider(&provider, PlatformInputs::default())
                .unwrap_err();
            assert!(
                matches!(error,InitializationError::Intel(Error::Resource(e)) if e.name=="intel/ibt-20-1-3.sfi" && matches!(e.kind,crate::firmware::ErrorKind::Missing))
            );
            assert_eq!(
                *provider.calls.borrow(),
                ["intel/ibt-20-1-3.sfi", "intel/ibt-20-1-3.ddc"]
            );
        }
        assert_eq!(hci.state(), State::Closed);
        assert_eq!(hci.test_io().submitted, 2);
        let provider = Recording {
            catalog: &catalog,
            calls: RefCell::new(Vec::new()),
        };
        assert!(
            hci.initialize_with_provider(&provider, PlatformInputs::default())
                .is_err()
        );
        assert!(provider.calls.borrow().is_empty());
        assert!(
            hci.submit_command(&command_bytes(READ_VERSION, &[0xff]))
                .is_err()
        );
        assert_eq!(hci.test_io().submitted, 2);
    }
    #[test]
    fn native_unknown_usb_device_stays_unverified_raw_without_vendor_commands() {
        for intel_vendor in [false, true] {
            let (mut device, catalog, script) = fixture();
            if intel_vendor {
                device.descriptor[10..12].copy_from_slice(&0xffffu16.to_le_bytes());
            } else {
                device.descriptor[8..10].copy_from_slice(&0x1234u16.to_le_bytes());
            }
            let mut hci = transport(device, script);
            let provider = Recording {
                catalog: &catalog,
                calls: RefCell::new(Vec::new()),
            };
            let error = hci
                .initialize_with_provider(&provider, PlatformInputs::default())
                .unwrap_err();
            assert!(
                matches!(error,InitializationError::UnsupportedDevice {vendor,product,revision:0x100}
                    if *vendor==if intel_vendor {0x8087} else {0x1234} && *product==if intel_vendor {0xffff} else {0x29})
            );
            assert_eq!(hci.test_io().submitted, 0);
            assert!(provider.calls.borrow().is_empty());
            assert_eq!(hci.state(), State::Open);
            assert_eq!(hci.firmware_status(), FirmwareStatus::Unverified);
        }
    }
    #[test]
    fn native_hci_usb_cleanup_and_partial_stage_failures_keep_typed_evidence() {
        for case in 0..4 {
            let (device, catalog, mut script) = if case == 3 {
                super::iml_tests::fixture_iml(0x1e, 1, false)
            } else {
                fixture()
            };
            if case == 0 || case == 2 {
                script.steps[2].events[0].1[5] = 0x0c;
            }
            let mut hci = transport(device, script);
            hci.test_io().fail_reset = case == 1;
            hci.test_io().fail_close = case == 2;
            let error = hci
                .initialize_with_provider(&catalog, PlatformInputs::default())
                .unwrap_err();
            match (case, error) {
                (
                    0,
                    InitializationError::Intel(Error::Controller {
                        opcode: SECURE_SEND,
                        status: 0x0c,
                    }),
                ) => {}
                (1, InitializationError::Intel(Error::Transport(e))) => assert!(matches!(
                    e.kind,
                    crate::usb::bluetooth::ErrorKind::Usb(BlockError::Unsupported(_))
                )),
                (2, InitializationError::Intel(Error::Cleanup { cause, cleanup })) => {
                    assert!(matches!(
                        **cause,
                        Error::Controller {
                            opcode: SECURE_SEND,
                            status: 0x0c
                        }
                    ));
                    assert!(matches!(
                        cleanup.kind,
                        crate::usb::bluetooth::ErrorKind::Usb(BlockError::Timeout)
                    ));
                }
                (
                    3,
                    InitializationError::Intel(Error::Stages {
                        cause,
                        completed,
                        pending,
                    }),
                ) => {
                    assert_eq!(completed.len(), 1);
                    assert_eq!(**pending, completed[0].after);
                    assert!(
                        matches!(**cause,Error::Resource(ref e) if e.name.ends_with("-usb.sfi"))
                    );
                }
                _ => panic!("typed native error lost"),
            }
            let submitted = hci.test_io().submitted;
            assert_ne!(hci.state(), State::Open);
            assert!(
                hci.initialize_with_provider(&catalog, PlatformInputs::default())
                    .is_err()
            );
            assert!(hci.submit_acl(&[1, 0, 0, 0]).is_err());
            assert_eq!(hci.test_io().submitted, submitted);
        }
    }
}

mod iml_tests {
    use super::*;
    use alloc::{format, string::String};
    use core::cell::RefCell;

    fn edit(payload: &[u8], kind: u8, value: Option<&[u8]>) -> Vec<u8> {
        let mut out = vec![0];
        let mut at = 1;
        while at < payload.len() {
            let n = usize::from(payload[at + 1]);
            if payload[at] != kind {
                out.extend_from_slice(&payload[at..at + 2 + n]);
            }
            at += 2 + n;
        }
        if let Some(v) = value {
            out.extend_from_slice(&[kind, v.len() as u8]);
            out.extend_from_slice(v);
        }
        out
    }
    fn observation(variant: u8, engine: u8, stage: u8, complete_security: bool) -> Vec<u8> {
        let mut p = tlv_version_variant(false, engine, variant);
        p = edit(&p, 0x10, Some(&0x0100_0900u32.to_le_bytes()));
        p = edit(&p, 0x1c, Some(&[stage]));
        if stage != 1 {
            p = edit(&p, 0x1f, Some(&9u32.to_le_bytes()));
            p = edit(&p, 0x50, Some(b"usb\0"));
            if !complete_security {
                for k in 0x28..=0x30 {
                    p = edit(&p, k, None);
                }
            }
        }
        p
    }
    fn add_upload(steps: &mut VecDeque<Step>, engine: u8, image: &[u8]) {
        // Independently spell the donor's complete RSA/ECDSA fragments, never use
        // production Sfi::sections to manufacture the expected command sequence.
        let sections: Vec<(u8, &[u8])> = if engine >= 2 {
            hybrid_fragments(image)
        } else if engine == 0 {
            vec![
                (0, &image[..128]),
                (3, &image[128..380]),
                (3, &image[380..384]),
                (2, &image[388..640]),
                (2, &image[640..644]),
                (1, &image[964..]),
            ]
        } else {
            vec![
                (0, &image[644..772]),
                (3, &image[772..868]),
                (2, &image[868..964]),
                (1, &image[964..]),
            ]
        };
        for (kind, bytes) in sections {
            let mut p = vec![kind];
            p.extend_from_slice(bytes);
            steps.push_back(Step {
                command: command_bytes(SECURE_SEND, &p),
                bulk: true,
                events: vec![(Pipe::Acl, complete(SECURE_SEND, &[0]))],
            });
        }
        steps.back_mut().unwrap().events[0]
            .1
            .extend_from_slice(&[0xff, 5, 6, 0, 9, 0xfc, 0]);
        steps.push_back(Step {
            command: command_bytes(INTEL_RESET, &[0, 1, 0, 1, 0, 0, 0x20, 0]),
            bulk: false,
            events: vec![(Pipe::Acl, vec![0xff, 7, 2, 0, 1, 0, 0, 0, 0])],
        });
    }
    pub(super) fn add_command(
        steps: &mut VecDeque<Step>,
        opcode: u16,
        params: &[u8],
        payload: &[u8],
    ) {
        steps.push_back(Step {
            command: command_bytes(opcode, params),
            bulk: false,
            events: vec![(Pipe::Event, complete(opcode, payload))],
        });
    }
    fn resources(device: &Device, initial: &[u8], iml: &[u8], include_stage2: bool) -> Catalog {
        let first = TlvIdentity::parse(device, initial).unwrap();
        let second = TlvIdentity::parse(device, iml).unwrap();
        let hardware = first.hardware_label();
        let revision1 = first.revision_label();
        let revision2 = second.iml_revision_label(&first);
        let name1 = first.filename("sfi");
        let name2 = second.filename("sfi");
        let ddc = second.filename("ddc");
        let provenance = Provenance {
            source: "Stela synthetic IML model",
            revision: "1",
            member: "synthetic/iml",
            license: "MIT",
        };
        let mut entries = Vec::new();
        let image = if first.secure_engine.is_some_and(|engine| engine >= 2) {
            hybrid_image()
        } else {
            combined_image()
        };
        for (name, revision, bytes) in [
            (name1.as_str(), revision1.as_str(), image.clone()),
            (name2.as_str(), revision2.as_str(), image),
            (ddc.as_str(), revision2.as_str(), vec![3, 1, 2, 0xaa]),
        ] {
            if !include_stage2 && !entries.is_empty() {
                break;
            }
            entries.push(Resource {
                name,
                target: first.target(&hardware, revision),
                provenance,
                expected_length: bytes.len(),
                expected_sha256: Sha256::digest(&bytes).into(),
                bytes,
            });
        }
        Catalog::from_handoff(entries).unwrap()
    }
    pub(super) fn fixture_iml(
        variant: u8,
        engine: u8,
        include_stage2: bool,
    ) -> (Device, Catalog, Script) {
        let (mut device, _, _) = fixture();
        device.descriptor[10] = 0x35;
        let initial = observation(variant, engine, 1, true);
        let iml = observation(variant, engine, 2, false);
        let op = observation(variant, engine, 3, false);
        let catalog = resources(&device, &initial, &iml, include_stage2);
        let mut steps = VecDeque::new();
        add_command(&mut steps, READ_VERSION, &[0xff], &initial);
        let image = if engine >= 2 {
            hybrid_image()
        } else {
            combined_image()
        };
        add_upload(&mut steps, engine, &image);
        add_command(&mut steps, READ_VERSION, &[0xff], &iml);
        if matches!(variant, 0x1e | 0x1f | 0x22) {
            add_command(&mut steps, SET_DSBR, &[0, 0], &[0]);
        }
        add_upload(&mut steps, engine, &image);
        add_command(&mut steps, READ_VERSION, &[0xff], &op);
        add_command(&mut steps, READ_BD_ADDR, &[], &[0, 1, 2, 3, 4, 5, 6]);
        add_command(&mut steps, WRITE_DDC, &[3, 1, 2, 0xaa], &[0]);
        add_command(&mut steps, READ_VERSION, &[0xff], &op);
        (device, catalog, Script { steps })
    }
    #[test]
    fn each_hybrid_lms_fragment_requires_a_real_success_and_keeps_completed_stage_on_fault() {
        let (_, _, reference) = fixture_iml(0x20, 3, true);
        let indices: Vec<usize> = reference
            .steps
            .iter()
            .enumerate()
            .filter_map(|(index, step)| {
                (step.command[..2] == SECURE_SEND.to_le_bytes() && matches!(step.command[3], 4 | 5))
                    .then_some(index)
            })
            .collect();
        assert_eq!(indices.len(), 16);
        for (ordinal, index) in indices.into_iter().enumerate() {
            let (device, catalog, mut script) = fixture_iml(0x20, 3, true);
            script.steps[index].events = vec![(Pipe::Acl, complete(SECURE_SEND, &[0x0c]))];
            let mut hci = transport(device, script);
            let error = initialize(&mut hci, &catalog).unwrap_err();
            let cause = if ordinal < 8 {
                &error
            } else {
                let Error::Stages {
                    completed,
                    pending,
                    cause,
                } = &error
                else {
                    panic!("completed hybrid IML evidence lost: {error:?}")
                };
                assert_eq!(completed.len(), 1);
                assert_eq!(completed[0].firmware.name, "intel/ibt-0190-0041-iml.sfi");
                assert!(
                    matches!(pending.as_ref(), ControllerIdentity::Tlv(i) if i.image_type == 2)
                );
                cause.as_ref()
            };
            assert!(matches!(
                cause,
                Error::Controller {
                    opcode: SECURE_SEND,
                    status: 0x0c
                }
            ));
            assert_eq!(hci.state(), State::Closed);
            let submitted = hci.test_io().submitted;
            assert!(initialize(&mut hci, &catalog).is_err());
            assert_eq!(hci.test_io().submitted, submitted);
        }
    }
    #[test]
    fn hybrid_engines_boot_through_iml_with_per_fragment_events() {
        for variant in [0x20, 0x21, 0x22] {
            for engine in [2, 3] {
                let (device, catalog, script) = fixture_iml(variant, engine, true);
                let mut hci = transport(device, script);
                let report = initialize(&mut hci, &catalog).unwrap();
                assert!(report.after.is_operational());
                assert_eq!(report.stages.len(), 2);
                assert_eq!(report.address, [1, 2, 3, 4, 5, 6]);
                assert!(
                    report.stages[1]
                        .inherited
                        .contains(&InheritedField::SecureEngine)
                );
                let ControllerIdentity::Tlv(before) = &report.stages[0].before else {
                    unreachable!()
                };
                assert_eq!(before.hardware_variant(), variant);
                assert_eq!(before.secure_engine, Some(engine));
                assert_eq!(
                    report.stages[0].dsbr.applied,
                    (variant == 0x22).then_some([0, 0])
                );
                assert!(hci.test_io().script.steps.is_empty());
                assert_eq!(hci.state(), State::Open);
            }
        }
    }
    #[test]
    fn iml_observation_selects_second_stage_and_preserves_raw_inherited_inputs() {
        for variant in [0x1e, 0x1f, 0x22] {
            for engine in [0, 1] {
                let (device, catalog, script) = fixture_iml(variant, engine, true);
                let mut hci = transport(device, script);
                let report = initialize(&mut hci, &catalog).unwrap();
                assert!(report.after.is_operational());
                assert_eq!(report.stages.len(), 2);
                let FirmwareEvidence::MultiStage {
                    firmware,
                    configuration,
                } = report.evidence
                else {
                    panic!("two actual uploads required")
                };
                assert_eq!(firmware[0].name(), "intel/ibt-0190-0041-iml.sfi");
                assert_eq!(firmware[1].name(), "intel/ibt-0190-0041-usb.sfi");
                assert_eq!(configuration.name(), "intel/ibt-0190-0041-usb.ddc");
                assert!(
                    firmware[1]
                        .target()
                        .revision
                        .starts_with("tlv-iml-v1:sha256:")
                );
                let ControllerIdentity::Tlv(iml) = &report.stages[1].before else {
                    unreachable!()
                };
                assert_eq!(iml.secure_engine, None);
                assert_eq!(iml.minimum_build, None);
                assert_eq!(iml.address, None);
                assert_eq!(
                    report.stages[1].inherited,
                    vec![
                        InheritedField::SecureBoot,
                        InheritedField::IndividualCompletions,
                        InheritedField::SecureEngine,
                        InheritedField::MinimumBuild,
                        InheritedField::OtpAddress,
                        InheritedField::OtpLock,
                        InheritedField::ApiLock,
                        InheritedField::DebugLock
                    ]
                );
                assert!(report.stages[0].inherited.is_empty());
                assert_eq!(report.stages[0].dsbr.applied, Some([0, 0]));
                assert_eq!(report.stages[1].dsbr.applied, None);
                assert!(hci.test_io().script.steps.is_empty());
                assert_eq!(hci.test_io().quiesced, 2);
                assert_eq!(hci.state(), State::Open);
                assert_eq!(
                    hci.firmware_status(),
                    crate::usb::bluetooth::FirmwareStatus::Unverified
                );
            }
        }
    }
    struct Recording<'a> {
        catalog: &'a Catalog,
        calls: RefCell<Vec<(String, String)>>,
    }
    impl Provider for Recording<'_> {
        fn load(
            &self,
            r: Requirement<'_>,
        ) -> core::result::Result<Image<'_>, crate::firmware::Error> {
            self.calls
                .borrow_mut()
                .push((r.name.into(), r.target.revision.into()));
            self.catalog.load(r)
        }
    }
    #[test]
    fn missing_later_resources_capture_both_companions_and_completed_stage_without_upload() {
        let (device, catalog, script) = fixture_iml(0x1e, 1, false);
        let provider = Recording {
            catalog: &catalog,
            calls: RefCell::new(Vec::new()),
        };
        let mut hci = transport(device, script);
        let error = initialize(&mut hci, &provider).unwrap_err();
        let calls = provider.calls.borrow();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].0, "intel/ibt-0190-0041-iml.sfi");
        assert_eq!(calls[1].0, "intel/ibt-0190-0041-usb.sfi");
        assert_eq!(calls[2].0, "intel/ibt-0190-0041-usb.ddc");
        assert_eq!(calls[1].1, calls[2].1);
        assert!(calls[1].1.starts_with("tlv-iml-v1:sha256:"));
        let Error::Stages {
            cause,
            completed,
            pending,
        } = error
        else {
            panic!("retain completed boot")
        };
        assert!(matches!(*cause,Error::Resource(ref e) if e.name==calls[1].0));
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].firmware.name, calls[0].0);
        assert_eq!(*pending, completed[0].after);
        assert!(!pending.is_operational());
        assert!(hci.test_io().script.steps.front().unwrap().bulk);
        assert_eq!(hci.state(), State::Closed);
    }
    #[test]
    fn each_stage_requires_fresh_secure_result_boot_event_and_matching_iml_identity() {
        for case in 0..5 {
            let (device, catalog, mut script) = fixture_iml(0x1e, 1, true);
            // 0 version, 1..4 secure, 5 reset, 6 IML version, 7 DSBR,
            // 8..11 secure, 12 reset, 13 operational version.
            match case {
                0 => script.steps[11].events[0].1.truncate(6),
                1 => script.steps[12].events.clear(),
                2 => script.steps[12].events = vec![(Pipe::Acl, complete(INTEL_RESET, &[0]))],
                3 => {
                    let payload = edit(
                        &observation(0x1e, 1, 2, false),
                        0x10,
                        Some(&0x0100_001au32.to_le_bytes()),
                    );
                    script.steps[6].events[0].1 = complete(READ_VERSION, &payload);
                }
                _ => {
                    let payload = edit(&observation(0x1e, 1, 2, false), 0x2f, Some(&[0]));
                    script.steps[6].events[0].1 = complete(READ_VERSION, &payload);
                }
            }
            let mut hci = transport(device, script);
            assert!(initialize(&mut hci, &catalog).is_err(), "case {case}");
            assert_eq!(hci.state(), State::Closed);
        }
    }
    #[test]
    fn fresh_iml_must_supply_security_otp_and_minimum_without_invented_history() {
        let (mut device, _, _) = fixture();
        device.descriptor[10] = 0x35;
        let payload = observation(0x1e, 1, 2, false);
        let mut steps = VecDeque::new();
        add_command(&mut steps, READ_VERSION, &[0xff], &payload);
        let mut hci = transport(device.clone(), Script { steps });
        let empty = Catalog::from_handoff(vec![]).unwrap();
        assert!(matches!(
            initialize(&mut hci, &empty),
            Err(Error::Unsupported(_))
        ));
        assert_eq!(hci.test_io().submitted, 1);
        assert_eq!(hci.state(), State::Closed);
        let initial = TlvIdentity::parse(&device, &observation(0x1e, 1, 1, true)).unwrap();
        let iml = TlvIdentity::parse(&device, &payload).unwrap();
        assert!(iml.boot_requirements(Some(&initial)).is_ok());
        assert!(iml.boot_requirements(None).is_err());
        let complete = TlvIdentity::parse(&device, &observation(0x1e, 1, 2, true)).unwrap();
        assert!(complete.boot_requirements(None).is_ok());
    }
    #[test]
    fn composite_selector_binds_complete_canonical_stage_bytes_and_safe_firmware_id() {
        let (mut device, _, _) = fixture();
        device.descriptor[10] = 0x35;
        let initial = TlvIdentity::parse(&device, &observation(0x1e, 1, 1, true)).unwrap();
        let payload = observation(0x1e, 1, 2, false);
        let iml = TlvIdentity::parse(&device, &payload).unwrap();
        let mut exact = b"stela.intel-usb.iml-target\0v1\0".to_vec();
        for bytes in [initial.canonical_tlvs(), iml.canonical_tlvs()] {
            exact.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            exact.extend(bytes);
        }
        assert_eq!(
            iml.iml_revision_label(&initial),
            format!("tlv-iml-v1:sha256:{:x}", Sha256::digest(exact))
        );
        assert!(iml.iml_revision_label(&initial).len() < 256);
        let different = TlvIdentity::parse(&device, &edit(&payload, 0x90, Some(&[0xff]))).unwrap();
        assert_ne!(
            iml.iml_revision_label(&initial),
            different.iml_revision_label(&initial)
        );
        for invalid in [b"../usb".as_slice(), b"usb\0x", b"/usb", b"", &[b'a'; 64]] {
            let p = edit(&payload, 0x50, Some(invalid));
            if invalid.is_empty() {
                assert_eq!(
                    TlvIdentity::parse(&device, &p).unwrap().filename("sfi"),
                    "intel/ibt-0190-0041.sfi"
                );
            } else {
                assert!(TlvIdentity::parse(&device, &p).is_err());
            }
        }
    }

    #[test]
    fn fresh_complete_iml_uses_its_own_selector_and_keeps_preupload_dsbr() {
        let (mut device, _, _) = fixture();
        device.descriptor[10] = 0x35;
        let initial = observation(0x1f, 1, 2, true);
        let op = observation(0x1f, 1, 3, false);
        let identity = TlvIdentity::parse(&device, &initial).unwrap();
        let hardware = identity.hardware_label();
        let revision = identity.revision_label();
        let sfi_name = identity.filename("sfi");
        let ddc_name = identity.filename("ddc");
        let target = identity.target(&hardware, &revision);
        let provenance = Provenance {
            source: "Stela fresh IML model",
            revision: "1",
            member: "synthetic/fresh-iml",
            license: "MIT",
        };
        let sfi = combined_image();
        let ddc = vec![3, 1, 2, 0xaa];
        let catalog = Catalog::from_handoff(vec![
            Resource {
                name: &sfi_name,
                target,
                provenance,
                expected_length: sfi.len(),
                expected_sha256: Sha256::digest(&sfi).into(),
                bytes: sfi,
            },
            Resource {
                name: &ddc_name,
                target,
                provenance,
                expected_length: ddc.len(),
                expected_sha256: Sha256::digest(&ddc).into(),
                bytes: ddc,
            },
        ])
        .unwrap();
        let mut steps = VecDeque::new();
        add_command(&mut steps, READ_VERSION, &[0xff], &initial);
        add_command(&mut steps, SET_DSBR, &[0, 0], &[0]);
        add_upload(&mut steps, 1, &combined_image());
        add_command(&mut steps, READ_VERSION, &[0xff], &op);
        add_command(&mut steps, READ_BD_ADDR, &[], &[0, 1, 2, 3, 4, 5, 6]);
        add_command(&mut steps, WRITE_DDC, &[3, 1, 2, 0xaa], &[0]);
        add_command(&mut steps, READ_VERSION, &[0xff], &op);
        let mut hci = transport(device, Script { steps });
        let report = initialize(&mut hci, &catalog).unwrap();
        let FirmwareEvidence::Uploaded { firmware, .. } = report.evidence else {
            panic!("only one actual uploaded image")
        };
        assert!(firmware.target().revision.starts_with("tlv-v1:sha256:"));
        assert_eq!(report.stages.len(), 1);
        assert!(report.stages[0].inherited.is_empty());
        assert_eq!(report.stages[0].dsbr_before.applied, Some([0, 0]));
        assert!(hci.test_io().script.steps.is_empty());
    }
    #[test]
    fn iml_dsbr_policy_matches_usb_generation_image_and_cnvi_step() {
        let (mut device, _, _) = fixture();
        device.descriptor[10] = 0x35;
        for variant in [0x1e, 0x1f, 0x22] {
            for stage in [1, 2, 3] {
                for step in [0u32, 1, 2] {
                    let payload = edit(
                        &observation(variant, 1, stage, true),
                        0x10,
                        Some(&((step << 24) | 0x900).to_le_bytes()),
                    );
                    let identity =
                        ControllerIdentity::Tlv(TlvIdentity::parse(&device, &payload).unwrap());
                    let required = stage == 2 && (variant == 0x1f || step == 1);
                    let mut steps = VecDeque::new();
                    if required {
                        add_command(&mut steps, SET_DSBR, &[1, 11], &[0]);
                    }
                    let mut hci = transport(device.clone(), Script { steps });
                    let mut engine = Engine::new(
                        &mut hci,
                        DsbrInput::Present {
                            revision: 7,
                            raw: 0xb1,
                        },
                    );
                    let report = engine.apply_dsbr(&identity).unwrap();
                    assert_eq!(report.applied, required.then_some([1, 11]));
                    assert!(hci.test_io().script.steps.is_empty());
                }
            }
        }
    }
    #[test]
    fn rejected_second_boot_keeps_pending_identity_without_crediting_stage() {
        for contradictory_security in [false, true] {
            let (device, catalog, mut script) = fixture_iml(0x1e, 1, true);
            let payload = if contradictory_security {
                edit(&observation(0x1e, 1, 3, false), 0x2f, Some(&[0]))
            } else {
                edit(
                    &observation(0x1e, 1, 3, false),
                    0x1f,
                    Some(&10u32.to_le_bytes()),
                )
            };
            let actual = ControllerIdentity::Tlv(TlvIdentity::parse(&device, &payload).unwrap());
            script.steps[13].events[0].1 = complete(READ_VERSION, &payload);
            let mut hci = transport(device, script);
            let Error::Stages {
                cause,
                completed,
                pending,
            } = initialize(&mut hci, &catalog).unwrap_err()
            else {
                panic!("completed IML retained")
            };
            assert_eq!(completed.len(), 1);
            let Error::RejectedBoot { cause, observation } = *cause else {
                panic!("rejected boot retained separately")
            };
            assert!(matches!(*cause, Error::Protocol(_)));
            assert_eq!(*pending, actual);
            assert_eq!(observation.after, actual);
            assert_ne!(completed[0].after, actual);
            assert_eq!(observation.before, completed[0].after);
            assert_eq!(observation.firmware.name, "intel/ibt-0190-0041-usb.sfi");
            assert_eq!(
                observation.firmware.sha256,
                Sha256::digest(combined_image())[..]
            );
            assert_eq!(observation.boot_notification, [0, 1, 0, 0, 0, 0]);
            assert_eq!(hci.state(), State::Closed);
            assert_eq!(
                hci.test_io().script.steps.front().unwrap().command[..2],
                READ_BD_ADDR.to_le_bytes()
            );
        }
    }
}

#[test]
fn intel_initializer_uses_xhci_dma_and_reframes_bulk_after_acknowledged_stop() {
    use crate::usb::bluetooth::{FirmwareStatus, Packet, intel};
    let mut dma = TestRegion::new(128 * 1024 * 8);
    let (controller, model) = unconfigured_cancellation_controller(&mut dma);
    let shared: Shared = Rc::new(RefCell::new(controller));
    let (mut device, catalog, script) = intel::tests::fixture();
    device.id = shared.borrow().test_device_id(device.slot).unwrap();
    let mut found = Found::default();
    bind(&shared, device, &mut dma, &mut found);
    assert!(found.failures.is_empty(), "{:?}", found.failures);
    let mut hci = found.bluetooth.pop().unwrap();
    model.borrow_mut().script = Some(script);
    let report = intel::initialize(&mut hci, &catalog).unwrap();
    assert!(report.after.is_operational());
    assert!(model.borrow().script.as_ref().unwrap().steps.is_empty());
    assert_eq!(model.borrow().outgoing.len(), 6);
    assert!(model.borrow().outgoing.iter().all(|p| p[..2] == [9, 0xfc]));
    // Entry cancels the idle posted bulk IN via Running Stop -> Stopped
    // Set Dequeue. Exit follows its completed boot-event TD; no hardware
    // ownership remains to cancel before restoring ordinary ACL framing.
    assert_eq!(
        model
            .borrow()
            .seen
            .iter()
            .filter(|&&kind| kind == STOP_ENDPOINT)
            .count(),
        1
    );
    assert_eq!(model.borrow().dequeues.len(), 1);
    assert_eq!(hci.firmware_status(), FirmwareStatus::Unverified);
    assert!(hci.poll().unwrap().is_empty());
    model
        .borrow_mut()
        .incoming_acl
        .push_back(vec![1, 0x20, 2, 0, 0xaa, 0xbb]);
    assert_eq!(
        hci.poll().unwrap(),
        vec![Packet::Acl(vec![1, 0x20, 2, 0, 0xaa, 0xbb])]
    );
}
