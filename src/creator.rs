// Copyright (c) 2017,2018 Ivaylo Petrov
//
// Licensed under the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
//
// author: Ivaylo Petrov <ivajloip@gmail.com>

use heapless;
use heapless::consts::*;

type Vec<T> = heapless::Vec<T,U256>;

use super::keys;
use super::maccommandcreator;
use super::maccommands;
use super::securityhelpers;
use crate::parser;

const PIGGYBACK_MAC_COMMANDS_MAX_LEN: usize = 15;


/// DataPayloadCreator serves for creating binary representation of Physical
/// Payload of DataUp or DataDown messages.
#[derive(Default)]
pub struct DataPayloadCreator {
    data: Vec<u8>,
    mac_commands_bytes: Vec<u8>,
    encrypt_mac_commands: bool,
    data_f_port: Option<u8>,
    fcnt: u32,
}

impl DataPayloadCreator {
    /// Creates a well initialized DataPayloadCreator.
    ///
    /// By default the packet is unconfirmed data up packet.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut phy = lorawan::creator::DataPayloadCreator::new();
    /// let nwk_skey = lorawan::keys::AES128([2; 16]);
    /// let app_skey = lorawan::keys::AES128([1; 16]);
    /// let fctrl = lorawan::parser::FCtrl::new(0x80, true);
    /// phy.set_confirmed(false);
    /// phy.set_uplink(true);
    /// phy.set_f_port(1);
    /// phy.set_dev_addr(&[4, 3, 2, 1]);
    /// phy.set_fctrl(&fctrl); // ADR: true, all others: false
    /// phy.set_fcnt(1);
    /// let payload = phy.build(b"hello", &nwk_skey, &app_skey).unwrap();
    /// ```
    pub fn new() -> DataPayloadCreator {
        let mut data = Vec::new();
        data.extend_from_slice(&[0; 12]).unwrap();
        data[0] = 0x40;
        DataPayloadCreator {
            data,
            ..Default::default()
        }
    }

    /// Sets whether the packet is uplink or downlink.
    ///
    /// # Argument
    ///
    /// * uplink - whether the packet is uplink or downlink.
    pub fn set_uplink(&mut self, uplink: bool) -> &mut DataPayloadCreator {
        if uplink {
            self.data[0] &= 0xdf;
        } else {
            self.data[0] |= 0x20;
        }
        self
    }

    /// Sets whether the packet is confirmed or unconfirmed.
    ///
    /// # Argument
    ///
    /// * confirmed - whether the packet is confirmed or unconfirmed.
    pub fn set_confirmed(&mut self, confirmed: bool) -> &mut DataPayloadCreator {
        if confirmed {
            self.data[0] &= 0xbf;
            self.data[0] |= 0x80;
        } else {
            self.data[0] &= 0x7f;
            self.data[0] |= 0x40;
        }

        self
    }

    /// Sets the device address of the DataPayload to the provided value.
    ///
    /// # Argument
    ///
    /// * dev_addr - instance of lorawan::parser::DevAddr or anything that can
    ///   be converted into it.
    pub fn set_dev_addr<'a, T: Into<parser::DevAddr<'a>>>(
        &mut self,
        dev_addr: T,
    ) -> &mut DataPayloadCreator {
        let converted = dev_addr.into();
        self.data[1..5].copy_from_slice(converted.as_ref());

        self
    }

    /// Sets the FCtrl header of the DataPayload packet to the specified value.
    ///
    /// # Argument
    ///
    /// * fctrl - the FCtrl to be set.
    pub fn set_fctrl(&mut self, fctrl: &parser::FCtrl) -> &mut DataPayloadCreator {
        self.data[5] = fctrl.raw_value();
        self
    }

    /// Sets the FCnt header of the DataPayload packet to the specified value.
    ///
    /// NOTE: In the packet header the value will be truncated to u16.
    ///
    /// # Argument
    ///
    /// * fctrl - the FCtrl to be set.
    pub fn set_fcnt(&mut self, fcnt: u32) -> &mut DataPayloadCreator {
        self.fcnt = fcnt;
        self.data[6] = (fcnt & (0xff as u32)) as u8;
        self.data[7] = (fcnt >> 8) as u8;

        self
    }

    /// Sets the FPort header of the DataPayload packet to the specified value.
    ///
    /// If f_port == 0, automatically sets `encrypt_mac_commands` to `true`.
    ///
    /// # Argument
    ///
    /// * f_port - the FPort to be set.
    pub fn set_f_port(&mut self, f_port: u8) -> &mut DataPayloadCreator {
        if f_port == 0 {
            self.encrypt_mac_commands = true;
        }
        self.data_f_port = Some(f_port);

        self
    }

    /// Sets the mac commands to be used.
    ///
    /// Based on f_port value and value of encrypt_mac_commands, the mac commands will be sent
    /// either as payload or piggybacked.
    ///
    /// # Examples:
    ///
    /// ```
    /// let mut phy = lorawan::creator::DataPayloadCreator::new();
    /// let mac_cmd1 = lorawan::maccommands::MacCommand::LinkCheckReq(
    ///     lorawan::maccommands::LinkCheckReqPayload());
    /// let mut mac_cmd2 = lorawan::maccommandcreator::LinkADRAnsCreator::new();
    /// mac_cmd2
    ///     .set_channel_mask_ack(true)
    ///     .set_data_rate_ack(false)
    ///     .set_tx_power_ack(true);
    /// let cmds: Vec<&lorawan::maccommands::SerializableMacCommand> = vec![&mac_cmd1, &mac_cmd2];
    /// phy.set_mac_commands(cmds);
    /// ```
    pub fn set_mac_commands<'a>(
        &'a mut self,
        cmds: Vec<&dyn maccommands::SerializableMacCommand>,
    ) -> &mut DataPayloadCreator {
        self.mac_commands_bytes = maccommandcreator::build_mac_commands(&cmds[..]);

        self
    }

    /// Whether the mac commands should be encrypted.
    ///
    /// NOTE: Setting the f_port to 0 implicitly sets the mac commands to be encrypted.
    pub fn set_encrypt_mac_commands(&mut self, encrypt: bool) -> &mut DataPayloadCreator {
        self.encrypt_mac_commands = encrypt;

        self
    }

    /// Whether a set of mac commands can be piggybacked.
    pub fn can_piggyback(cmds: Vec<&dyn maccommands::SerializableMacCommand>) -> bool {
        maccommands::mac_commands_len(&cmds[..]) <= PIGGYBACK_MAC_COMMANDS_MAX_LEN
    }

    /// Provides the binary representation of the DataPayload physical payload
    /// with the MIC set and payload encrypted.
    ///
    /// # Argument
    ///
    /// * payload - the FRMPayload (application) to be sent.
    /// * nwk_skey - the key to be used for setting the MIC and possibly for
    ///   MAC command encryption.
    /// * app_skey - the key to be used for payload encryption if fport not 0,
    ///   otherwise nwk_skey is only used.
    pub fn build(
        &mut self,
        payload: &[u8],
        nwk_skey: &keys::AES128,
        app_skey: &keys::AES128,
    ) -> Result<&[u8], &str> {
        let mut last_filled = 8; // MHDR + FHDR without the FOpts
        let has_fport = self.data_f_port.is_some();
        let has_fport_zero = has_fport && self.data_f_port.unwrap() == 0;

        // Set MAC Commands
        if self.mac_commands_bytes.len() > PIGGYBACK_MAC_COMMANDS_MAX_LEN && has_fport
            && self.data_f_port.unwrap() != 0
        {
            return Err("mac commands are too big for FOpts");
        }
        if self.encrypt_mac_commands && has_fport && !has_fport_zero {
            return Err("mac commands in payload require FPort == 0");
        }
        if !self.encrypt_mac_commands && has_fport_zero {
            return Err("mac commands have to be encrypted when FPort is 0");
        }

        // Set FPort
        let mut payload_len = payload.len();
        if has_fport_zero && payload_len > 0 {
            return Err("mac commands in payload can not be send together with payload");
        }
        if !has_fport && payload_len > 0 {
            return Err("fport must be provided when there is FRMPayload");
        }
        // Set FOptsLen if present
        if !self.encrypt_mac_commands && !self.mac_commands_bytes.is_empty() {
            let mac_cmds_len = self.mac_commands_bytes.len();
            self.data[5] |= mac_cmds_len as u8 & 0x0f;
            self.data[last_filled..last_filled + mac_cmds_len]
                .copy_from_slice(&self.mac_commands_bytes[..]);
            last_filled += mac_cmds_len;
        }
        if has_fport {
            self.data[last_filled] = self.data_f_port.unwrap();
            last_filled += 1;
        }

        // Encrypt FRMPayload
        let encrypted_payload = if has_fport_zero {
            payload_len = self.mac_commands_bytes.len();
            securityhelpers::encrypt_frm_data_payload(
                &self.data[..],
                &self.mac_commands_bytes[..],
                self.fcnt,
                nwk_skey,
            )?
        } else {
            securityhelpers::encrypt_frm_data_payload(
                &self.data[..],
                payload,
                self.fcnt,
                app_skey,
            )?
        };

        // Set payload if possible, otherwise return error
        let additional_bytes_needed = last_filled + payload_len + 4 - self.data.len();
        if additional_bytes_needed > 0 {
            // we don't have enough length to accomodate all the bytes
            return Err("not enough Array space");
        }
        if payload_len > 0 {
            self.data[last_filled..last_filled + payload_len]
                .copy_from_slice(&encrypted_payload[..]);
        }

        // MIC set
        let len = self.data.len();
        let mic = securityhelpers::calculate_data_mic(&self.data[..len - 4], nwk_skey, self.fcnt);
        self.data[len - 4..].copy_from_slice(&mic.0[..]);

        Ok(&self.data[..])
    }
}
