// Copyright (c) 2017,2018 Ivaylo Petrov
//
// Licensed under the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
//
// author: Ivaylo Petrov <ivajloip@gmail.com>

extern crate lorawan;

use lorawan::creator::*;
use lorawan::keys::*;
use lorawan::maccommandcreator::*;
use lorawan::maccommands::*;
use lorawan::parser::*;

fn phy_join_request_payload() -> Vec<u8> {
    vec![
        0x00, 0x04, 0x03, 0x02, 0x01, 0x04, 0x03, 0x02, 0x01, 0x05, 0x04, 0x03, 0x02, 0x05, 0x04,
        0x03, 0x02, 0x2d, 0x10, 0x6a, 0x99, 0x0e, 0x12,
    ]
}

fn phy_join_accept_payload() -> Vec<u8> {
    vec![
        0x20, 0x49, 0x3e, 0xeb, 0x51, 0xfb, 0xa2, 0x11, 0x6f, 0x81, 0x0e, 0xdb, 0x37, 0x42, 0x97,
        0x51, 0x42,
    ]
}

fn join_accept_payload_with_c_f_list() -> Vec<u8> {
    vec![
        0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x04, 0x03, 0x02, 0x01, 0x67, 0x09, 0x18, 0x4f, 0x84,
        0xe8, 0x56, 0x84, 0xb8, 0x5e, 0x84, 0x88, 0x66, 0x84, 0x58, 0x6e, 0x84, 0,
    ]
    //867100000, 867300000, 867500000, 867700000, 867900000
}

fn data_payload() -> Vec<u8> {
    vec![
        0x40, 0x04, 0x03, 0x02, 0x01, 0x80, 0x01, 0x00, 0x01, 0xa6, 0x94, 0x64, 0x26, 0x15, 0xd6,
        0xc3, 0xb5, 0x82,
    ]
}

fn data_payload_with_fport_zero() -> Vec<u8> {
    vec![
        0x40, 0x04, 0x03, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x69, 0x36, 0x9e, 0xee, 0x6a, 0xa5,
        0x08,
    ]
}

fn data_payload_with_f_opts() -> Vec<u8> {
    vec![
        0x40, 0x04, 0x03, 0x02, 0x01, 0x03, 0x00, 0x00, 0x02, 0x03, 0x05, 0xd7, 0xfa, 0x0c, 0x6c
    ]
}

fn app_key() -> [u8; 16] {
    [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ]
}

#[test]
fn test_mhdr_mtype() {
    let examples = [
        (0x00, MType::JoinRequest),
        (0x20, MType::JoinAccept),
        (0x40, MType::UnconfirmedDataUp),
        (0x60, MType::UnconfirmedDataDown),
        (0x80, MType::ConfirmedDataUp),
        (0xa0, MType::ConfirmedDataDown),
        (0xc0, MType::RFU),
        (0xe0, MType::Proprietary),
    ];
    for &(ref v, ref expected) in &examples {
        let mhdr = MHDR::new(*v);
        assert_eq!(mhdr.mtype(), *expected);
    }
}

#[test]
fn test_mhdr_major() {
    let examples = [(0, Major::LoRaWANR1), (1, Major::RFU)];
    for &(ref v, ref expected) in &examples {
        let mhdr = MHDR::new(*v);
        assert_eq!(mhdr.major(), *expected);
    }
}

#[test]
fn test_mic() {
    let bytes = &data_payload()[..];
    let phy = PhyPayload::new(bytes);

    assert!(phy.is_ok());
    assert_eq!(phy.unwrap().mic(), MIC([0xd6, 0xc3, 0xb5, 0x82]));
}

#[test]
fn test_phy_payload_is_none_when_too_few_bytes() {
    let bytes = &vec![
        0x80, 0x04, 0x03, 0x02, 0x01, 0x00, 0xff, 0x01, 0x02, 0x03, 0x04
    ];
    let phy = PhyPayload::new(bytes);
    assert!(phy.is_err());
}

#[test]
fn test_new_data_payload_is_none_if_bytes_too_short() {
    let bytes = &[0x04, 0x03, 0x02, 0x01, 0x00, 0xff];
    let bytes_with_fopts = &[0x04, 0x03, 0x02, 0x01, 0x01, 0xff, 0x04];

    assert!(DataPayload::new(bytes, true).is_none());
    assert!(DataPayload::new(bytes_with_fopts, true).is_none());
}

#[test]
fn test_f_port_could_be_absent_in_data_payload() {
    let bytes = &[0x04, 0x03, 0x02, 0x01, 0x00, 0xff, 0x04];
    let data_payload = DataPayload::new(bytes, true);
    assert!(data_payload.is_some());
    assert!(data_payload.unwrap().f_port().is_none());
}

#[test]
fn test_new_join_accept_payload_mic_validation() {
    let mut data = phy_join_accept_payload();
    let key = AES128(app_key());
    {
        let phy = PhyPayload::new(&data[..]).unwrap();
        assert_eq!(phy.validate_join_mic(&key), Ok(false));
    }

    let decrypted_phy = PhyPayload::new_decrypted_join_accept(&mut data[..], &key).unwrap();
    assert_eq!(decrypted_phy.validate_join_mic(&key), Ok(true));
}

#[test]
fn test_new_join_accept_payload() {
    let bytes = &phy_join_accept_payload()[1..13];

    assert!(JoinAcceptPayload::new(&bytes[1..]).is_none());
    assert!(JoinAcceptPayload::new(bytes).is_some());
    let ja = JoinAcceptPayload::new(bytes).unwrap();

    assert_eq!(ja.c_f_list(), Vec::new());
}

#[test]
fn test_join_accept_app_nonce_extraction() {
    let bytes = &phy_join_accept_payload();
    let join_accept = JoinAcceptPayload::new(&bytes[1..13]);
    assert!(join_accept.is_some());

    assert_eq!(
        join_accept.unwrap().app_nonce(),
        AppNonce::new(&bytes[1..4]).unwrap()
    );
}

#[test]
fn test_join_accept_rx_delay_extraction() {
    let bytes = &phy_join_accept_payload();
    let join_accept = JoinAcceptPayload::new(&bytes[1..13]);
    assert!(join_accept.is_some());

    assert_eq!(join_accept.unwrap().rx_delay(), 7);
}

#[test]
fn test_join_accept_dl_settings_extraction() {
    let bytes = &phy_join_accept_payload();
    let join_accept = JoinAcceptPayload::new(&bytes[1..13]);
    assert!(join_accept.is_some());

    assert_eq!(join_accept.unwrap().dl_settings(), DLSettings::new(219));
}

#[test]
fn test_dl_settings() {
    let dl_settings = DLSettings::new(0xcb);
    assert_eq!(dl_settings.rx1_dr_offset(), 4);
    assert_eq!(dl_settings.rx2_data_rate(), 11);
}

#[test]
fn test_new_join_accept_payload_with_c_f_list() {
    let bytes = &join_accept_payload_with_c_f_list()[..];

    let ja = JoinAcceptPayload::new(bytes).unwrap();
    let expected_c_f_list = vec![
        Frequency::new_from_raw(&[0x18, 0x4F, 0x84]),
        Frequency::new_from_raw(&[0xE8, 0x56, 0x84]),
        Frequency::new_from_raw(&[0xB8, 0x5E, 0x84]),
        Frequency::new_from_raw(&[0x88, 0x66, 0x84]),
        Frequency::new_from_raw(&[0x58, 0x6E, 0x84]),
    ];
    assert_eq!(ja.c_f_list(), expected_c_f_list);
}

#[test]
fn test_new_frequency() {
    let freq = Frequency::new(&[0x18, 0x4F, 0x84]);

    assert!(freq.is_some());
    assert_eq!(freq.unwrap().value(), 867100000);
}

#[test]
fn test_mac_payload_has_good_bytes_when_size_correct() {
    let bytes = &[
        0x80, 0x04, 0x03, 0x02, 0x01, 0x00, 0xff, 0xff, 0x01, 0x02, 0x03, 0x04
    ];
    let phy_res = PhyPayload::new(bytes);
    assert!(phy_res.is_ok());
    let phy = phy_res.unwrap();
    if let MacPayload::Data(data_payload) = phy.mac_payload() {
        let expected_bytes = &[0x04, 0x03, 0x02, 0x01, 0x00, 0xff, 0xff];
        let expected = DataPayload::new(expected_bytes, true).unwrap();

        assert_eq!(data_payload, expected)
    } else {
        panic!("failed to parse DataPayload: {:?}", phy.mac_payload());
    }
}

#[test]
fn test_complete_data_payload_f_port() {
    let data = data_payload();
    let phy = PhyPayload::new(&data[..]);

    assert!(phy.is_ok());
    if let MacPayload::Data(data_payload) = phy.unwrap().mac_payload() {
        assert_eq!(data_payload.f_port(), Some(1))
    } else {
        panic!("failed to parse DataPayload");
    }
}

#[test]
fn test_complete_data_payload_fhdr() {
    let data = data_payload();
    let phy = PhyPayload::new(&data[..]);

    assert!(phy.is_ok());
    if let MacPayload::Data(data_payload) = phy.unwrap().mac_payload() {
        let fhdr = data_payload.fhdr();

        assert_eq!(fhdr.dev_addr(), DevAddr::new(&[4, 3, 2, 1]).unwrap());

        assert_eq!(fhdr.fcnt(), 1u16);

        let fctrl = fhdr.fctrl();

        assert_eq!(fctrl.f_opts_len(), 0);

        assert!(!fctrl.f_pending(), "no f_pending");

        assert!(!fctrl.ack(), "no ack");

        assert!(fctrl.adr(), "ADR");
    } else {
        panic!("failed to parse DataPayload");
    }
}

#[test]
fn test_complete_data_payload_frm_payload() {
    let data = data_payload();
    let phy = PhyPayload::new(&data[..]);
    let key = AES128([1; 16]);

    assert!(phy.is_ok());
    assert_eq!(
        phy.unwrap().decrypted_payload(&key, 1),
        Ok(FRMPayload::Data(String::from("hello").into_bytes() as FRMDataPayload,))
    );
}

#[test]
fn test_validate_data_mic_when_ok() {
    let data = data_payload();
    let phy = PhyPayload::new(&data[..]);
    let key = AES128([2; 16]);

    assert!(phy.is_ok());
    assert_eq!(phy.unwrap().validate_data_mic(&key, 1), Ok(true));
}

#[test]
fn test_validate_data_mic_when_type_not_ok() {
    let bytes = [0; 23];
    let phy = PhyPayload::new(&bytes[..]);
    let key = AES128([2; 16]);

    assert!(phy.is_ok());
    assert_eq!(
        phy.unwrap().validate_data_mic(&key, 1),
        Err("Could not read mac payload, maybe of incorrect type")
    );
}

#[test]
fn test_data_payload_creator() {
    let mut phy = DataPayloadCreator::new();
    let nwk_skey = AES128([2; 16]);
    let app_skey = AES128([1; 16]);
    let fctrl = FCtrl::new(0x80, true);
    phy.set_confirmed(false)
        .set_uplink(true)
        .set_f_port(1)
        .set_dev_addr(&[4, 3, 2, 1])
        .set_fctrl(&fctrl) // ADR: true, all others: false
        .set_fcnt(1);

    assert_eq!(
        phy.build(b"hello", &nwk_skey, &app_skey).unwrap(),
        &data_payload()[..]
    );
}

#[test]
fn test_data_payload_creator_when_payload_and_fport_0() {
    let mut phy = DataPayloadCreator::new();
    let nwk_skey = AES128([2; 16]);
    let app_skey = AES128([1; 16]);
    phy.set_f_port(0);
    assert!(phy.build(b"hello", &nwk_skey, &app_skey).is_err());
}

#[test]
fn test_data_payload_creator_when_fport_0_but_not_encrypt() {
    let mut phy = DataPayloadCreator::new();
    let nwk_skey = AES128([2; 16]);
    let app_skey = AES128([1; 16]);
    phy.set_f_port(0).set_encrypt_mac_commands(false);
    assert!(phy.build(b"", &nwk_skey, &app_skey).is_err());
}

#[test]
fn test_data_payload_creator_when_encrypt_but_not_fport_0() {
    let mut phy = DataPayloadCreator::new();
    let nwk_skey = AES128([2; 16]);
    let app_skey = AES128([1; 16]);
    let new_channel_req = NewChannelReqPayload::new(&[0x00; 5]).unwrap().0;
    let cmds: Vec<&SerializableMacCommand> =
        vec![&new_channel_req, &new_channel_req, &new_channel_req];
    phy.set_f_port(1).set_mac_commands(cmds);
    assert!(phy.build(b"", &nwk_skey, &app_skey).is_err());
}

#[test]
fn test_data_payload_creator_when_big_mac_commands_but_not_fport_0() {
    let mut phy = DataPayloadCreator::new();
    let nwk_skey = AES128([2; 16]);
    let app_skey = AES128([1; 16]);
    phy.set_f_port(1).set_encrypt_mac_commands(true);
    assert!(phy.build(b"", &nwk_skey, &app_skey).is_err());
}

#[test]
fn test_data_payload_creator_when_payload_no_fport() {
    let mut phy = DataPayloadCreator::new();
    let nwk_skey = AES128([2; 16]);
    let app_skey = AES128([1; 16]);
    assert!(phy.build(b"hello", &nwk_skey, &app_skey).is_err());
}

#[test]
fn test_data_payload_creator_when_mac_commands_in_payload() {
    let mut phy = DataPayloadCreator::new();
    let nwk_skey = AES128([1; 16]);
    let mac_cmd1 = MacCommand::LinkCheckReq(LinkCheckReqPayload());
    let mut mac_cmd2 = LinkADRAnsCreator::new();
    mac_cmd2
        .set_channel_mask_ack(true)
        .set_data_rate_ack(false)
        .set_tx_power_ack(true);
    let cmds: Vec<&SerializableMacCommand> = vec![&mac_cmd1, &mac_cmd2];
    phy.set_confirmed(false)
        .set_uplink(true)
        .set_f_port(0)
        .set_dev_addr(&[4, 3, 2, 1])
        .set_fcnt(0)
        .set_mac_commands(cmds);
    assert_eq!(
        phy.build(b"", &nwk_skey, &nwk_skey).unwrap(),
        &data_payload_with_fport_zero()[..]
    );
}

#[test]
fn test_data_payload_creator_when_mac_commands_in_f_opts() {
    let mut phy = DataPayloadCreator::new();
    let nwk_skey = AES128([1; 16]);
    let mac_cmd1 = MacCommand::LinkCheckReq(LinkCheckReqPayload());
    let mut mac_cmd2 = LinkADRAnsCreator::new();
    mac_cmd2
        .set_channel_mask_ack(true)
        .set_data_rate_ack(false)
        .set_tx_power_ack(true);
    let cmds: Vec<&SerializableMacCommand> = vec![&mac_cmd1, &mac_cmd2];
    phy.set_confirmed(false)
        .set_uplink(true)
        .set_dev_addr(&[4, 3, 2, 1])
        .set_fcnt(0)
        .set_mac_commands(cmds);

    assert_eq!(
        phy.build(b"", &nwk_skey, &nwk_skey).unwrap(),
        &data_payload_with_f_opts()[..]
    );
}
// TODO: test data payload create with piggy_backed mac commands

#[test]
fn test_join_request_dev_eui_extraction() {
    let data = phy_join_request_payload();
    let phy = PhyPayload::new(&data[..]);

    assert!(phy.is_ok());
    if let MacPayload::JoinRequest(join_request) = phy.unwrap().mac_payload() {
        assert_eq!(join_request.dev_eui(), EUI64::new(&data[9..17]).unwrap());
    } else {
        panic!("failed to parse JoinRequest mac payload");
    }
}

#[test]
fn test_join_request_app_eui_extraction() {
    let data = phy_join_request_payload();
    let phy = PhyPayload::new(&data[..]);

    assert!(phy.is_ok());
    if let MacPayload::JoinRequest(join_request) = phy.unwrap().mac_payload() {
        assert_eq!(join_request.app_eui(), EUI64::new(&data[1..9]).unwrap());
    } else {
        panic!("failed to parse JoinRequest mac payload");
    }
}

#[test]
fn test_join_request_dev_nonce_extraction() {
    let data = phy_join_request_payload();
    let phy = PhyPayload::new(&data[..]);

    assert!(phy.is_ok());
    if let MacPayload::JoinRequest(join_request) = phy.unwrap().mac_payload() {
        assert_eq!(
            join_request.dev_nonce(),
            DevNonce::new(&data[17..19]).unwrap()
        );
    } else {
        panic!("failed to parse JoinRequest mac payload");
    }
}

#[test]
fn test_validate_join_request_mic_when_ok() {
    let data = phy_join_request_payload();
    let phy = PhyPayload::new(&data[..]);
    let key = AES128([1; 16]);

    assert!(phy.is_ok());
    assert_eq!(phy.unwrap().validate_join_mic(&key), Ok(true));
}

#[test]
fn test_join_accept_creator() {
    let mut phy = JoinAcceptCreator::new();
    let key = AES128(app_key());
    let app_nonce_bytes = [0xc7, 0x0b, 0x57];
    phy.set_app_nonce(&app_nonce_bytes)
        .set_net_id(&[0x01, 0x11, 0x22])
        .set_dev_addr(&[0x80, 0x19, 0x03, 0x02])
        .set_dl_settings(0)
        .set_rx_delay(0);

    assert_eq!(phy.build(&key).unwrap(), &phy_join_accept_payload()[..]);
}

#[test]
fn test_join_request_creator() {
    let mut phy = JoinRequestCreator::new();
    let key = AES128([1; 16]);
    phy.set_app_eui(&[0x04, 0x03, 0x02, 0x01, 0x04, 0x03, 0x02, 0x01])
        .set_dev_eui(&[0x05, 0x04, 0x03, 0x02, 0x05, 0x04, 0x03, 0x02])
        .set_dev_nonce(&[0x2du8, 0x10]);

    assert_eq!(phy.build(&key).unwrap(), &phy_join_request_payload()[..]);
}

#[test]
fn test_eui64_to_string() {
    let eui = EUI64::new(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff]).unwrap();
    assert_eq!(eui.to_string(), "123456789abcdeff".to_owned());
}
