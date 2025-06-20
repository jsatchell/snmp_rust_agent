//! Implementation of Agent
//!
//! Agent is the basic run time service.  See main.rs for a simple example of how
//! it might be used.

//pub use crate::engine_id;
use crate::keeper::OidErr;
use crate::oidmap::OidMap;
use crate::perms::Perm;
use crate::privacy;
use crate::usm;
use log::{debug, error, warn};
use rasn;
use rasn::types::{Integer, ObjectIdentifier, OctetString};
use rasn_smi::v2::{ObjectSyntax, SimpleSyntax};
use rasn_snmp::v2::{Pdu, Report, VarBind};
use rasn_snmp::v3::VarBindValue;
use rasn_snmp::v3::{GetBulkRequest, GetNextRequest, GetRequest, SetRequest};
use rasn_snmp::v3::{HeaderData, Message, Pdus, ScopedPdu, USMSecurityParameters};
use rasn_snmp::v3::{Response, ScopedPduData};
use std::fmt::Display;
use std::fs::{read_to_string, write};
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::str::FromStr;
use std::time::Instant;

const BOOTCNT_FILENAME: &str = "boot-cnt.txt";
const B12: [u8; 12] = [0; 12];
const Z12: OctetString = OctetString::from_static(&B12);
const ZB: OctetString = OctetString::from_static(b"");

/// Get the boot count from non-volatile storage, creating file if it does not exist.
/// Panic if the file cannot be parsed or updated, as that indicates tampering or hardware failure.
fn get_increment_boot_cnt() -> isize {
    let mut boots: isize = 0;
    let cnt_res: Result<String, std::io::Error> = read_to_string(BOOTCNT_FILENAME);
    if let Ok(string) = cnt_res {
        boots = isize::from_str(&string).unwrap();
    }
    boots += 1;
    write(BOOTCNT_FILENAME, boots.to_string().as_bytes()).unwrap();
    boots
}

/// Main Agent object.
pub struct Agent {
    socket: UdpSocket,
    engine_id: OctetString,
    start_time: Instant,
    boots: isize,
    in_pkts: u64,
    unknown_engine_ids: u32,
    decode_error_cnt: u32,
}

impl Agent {
    /// Constructor for Agent
    ///
    /// eid is the engine id.
    ///
    /// addr_str is the address to listen on - often "0.0.0.0:161" can be a good choice
    /// But systems with multiple interfaces (like a firewall, router or crypto) might only listen
    /// on an internal address.
    pub fn build(eid: OctetString, addr_str: &str) -> Self {
        let sock = UdpSocket::bind(addr_str).expect("Couldn't bind to address");

        //let users = usm::load_users();
        Agent {
            socket: sock,
            engine_id: eid,
            start_time: Instant::now(),
            boots: get_increment_boot_cnt(),
            in_pkts: 0u64,
            unknown_engine_ids: 0u32,
            decode_error_cnt: 0u32,
        }
    }

    /// Internal method for supporting engine ID discovery by managers
    fn id_response(&self, request_id: i32, message_id: Integer) -> Message {
        let vb: Vec<VarBind> = vec![VarBind {
            name: ObjectIdentifier::new_unchecked(vec![1, 3, 6, 1, 6, 3, 15, 1, 1, 4].into()),
            value: VarBindValue::Value(ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(
                self.unknown_engine_ids,
            )))),
        }];

        let pdu = Pdu {
            request_id,
            error_index: 0,
            error_status: 0,
            variable_bindings: vb,
        };
        let report: Report = Report(pdu);
        let head = HeaderData {
            flags: OctetString::from_static(b"\x00"),
            message_id,
            max_size: Integer::from(65000),
            security_model: Integer::from(3),
        };
        let scpd: ScopedPdu = ScopedPdu {
            engine_id: self.engine_id.clone(),
            name: OctetString::from_static(b""),
            data: Pdus::Report(report),
        };
        let spd: ScopedPduData = ScopedPduData::CleartextPdu(scpd);
        let run_time: isize = self.start_time.elapsed().as_secs().try_into().unwrap();
        let usm: USMSecurityParameters = USMSecurityParameters {
            authoritative_engine_boots: Integer::from(self.boots),
            authoritative_engine_id: self.engine_id.clone(),
            authoritative_engine_time: Integer::from(run_time),
            user_name: ZB,
            authentication_parameters: ZB,
            privacy_parameters: ZB,
        };
        let mut message: Message = Message {
            version: Integer::from(3),
            global_data: head,
            scoped_data: spd,
            security_parameters: ZB,
        };
        _ = message.encode_security_parameters(rasn::Codec::Ber, &usm);
        message
    }

    /// Internal method that builds response packets.
    fn prepare_back(
        &self,
        message_id: Integer,
        resp: Response,
        opt_usr: Option<&usm::User>,
        usp: USMSecurityParameters,
    ) -> Message {
        // Return message with matching ids etc.
        let head = HeaderData {
            flags: OctetString::from_static(b"\x00"),
            message_id,
            max_size: Integer::from(65000),
            security_model: Integer::from(3),
        };
        let scpd: ScopedPdu = ScopedPdu {
            engine_id: self.engine_id.clone(),
            name: ZB,
            data: Pdus::Response(resp),
        };
        let user_name = match opt_usr {
            Some(user) => OctetString::copy_from_slice(&user.name),
            None => ZB,
        };
        let mut spd: ScopedPduData = ScopedPduData::CleartextPdu(scpd);
        let run_time: isize = self.start_time.elapsed().as_secs().try_into().unwrap();
        let mut usm: USMSecurityParameters = USMSecurityParameters {
            authoritative_engine_boots: Integer::from(self.boots),
            authoritative_engine_id: self.engine_id.clone(),
            authoritative_engine_time: Integer::from(run_time),
            user_name,
            authentication_parameters: ZB,
            privacy_parameters: ZB,
        };
        if opt_usr.is_some() {
            usm.privacy_parameters = usp.privacy_parameters.clone();
            let user = opt_usr.unwrap();
            let key = &user.priv_key;
            let enc_octs = rasn::ber::encode(&spd).unwrap();
            let value: Vec<u8> = privacy::encrypt(&mut enc_octs.to_vec(), usp, key);
            spd = ScopedPduData::EncryptedPdu(OctetString::from(value));
        }
        let mut output: Message = Message {
            version: Integer::from(3),
            global_data: head,
            scoped_data: spd,
            security_parameters: ZB,
        };

        _ = output.encode_security_parameters(rasn::Codec::Ber, &usm);
        output
    }

    fn get(
        &self,
        oid_map: &mut OidMap,
        r: GetRequest,
        vb: &mut Vec<VarBind>,
        perm: &Perm,
        flags: u8,
    ) -> (u32, u32, i32) {
        let mut error_status = Pdu::ERROR_STATUS_NO_ERROR;
        let mut error_index = 0;
        let request_id = r.0.request_id;
        let mut vb_cnt = 0;
        for vbind in r.0.variable_bindings {
            let roid = vbind.name.clone();
            if !perm.check(flags, false, &roid) {
                error_status = Pdu::ERROR_STATUS_NO_ACCESS;
                error_index = vb_cnt;
                return (error_status, error_index, request_id);
            }
            let opt_get: Result<usize, usize> = oid_map.search(&roid);
            match opt_get {
                Err(insert_point) => {
                    debug!("Get miss case {insert_point}");
                    let okeep = &mut oid_map.idx(insert_point - 1);
                    if okeep.is_scalar(roid.clone()) {
                        debug!("Scalar get ");
                        error_status = Pdu::ERROR_STATUS_NO_SUCH_NAME;
                        vb.push(VarBind {
                            name: roid,
                            value: VarBindValue::NoSuchObject,
                        });
                        error_index = vb_cnt;
                    } else {
                        debug!("Table get ");
                        let get_res = okeep.get(roid.clone());
                        debug!("Table get {get_res:?}");
                        match get_res {
                            Ok(res) => vb.push(VarBind {
                                name: roid.clone(),
                                value: res,
                            }),
                            Err(_) => {
                                error_status = Pdu::ERROR_STATUS_NO_SUCH_NAME;
                                vb.push(VarBind {
                                    name: roid,
                                    value: VarBindValue::NoSuchObject,
                                });
                            }
                        }
                    }
                }
                Ok(which) => {
                    vb_cnt += 1;
                    let okeep = &mut oid_map.idx(which);
                    let value_res = okeep.get(roid.clone());
                    if let Ok(value) = value_res {
                        vb.push(VarBind {
                            name: roid.clone(),
                            value,
                        });
                    } else {
                        error_status = Pdu::ERROR_STATUS_NO_SUCH_NAME;
                        vb.push(VarBind {
                            name: roid,
                            value: VarBindValue::NoSuchInstance,
                        });
                        error_index = vb_cnt;
                    }
                }
            }
        }
        (error_status, error_index, request_id)
    }

    fn do_next(
        &self,
        roid: ObjectIdentifier,
        oid_map: &mut OidMap,
        vb: &mut Vec<VarBind>,
        error_status: &mut u32,
        error_index: &mut u32,
        vb_cnt: u32,
        perm: &Perm,
        flags: u8,
    ) {
        if !perm.check(flags, false, &roid) {
            *error_status = Pdu::ERROR_STATUS_NO_ACCESS;
            *error_index = vb_cnt;
            return;
        }
        let opt_get: Result<usize, usize> = oid_map.search(&roid);
        match opt_get {
            Err(insert_point) => {
                debug!("Get next miss case {insert_point}");
                if insert_point == 0 {
                    // Off the front of our range - give the first thing
                    let oid1 = oid_map.oid(0).clone();
                    let okeep = &mut oid_map.idx(0);
                    if okeep.is_scalar(oid1.clone()) {
                        let value = okeep.get(oid1.clone()).unwrap();
                        vb.push(VarBind {
                            name: oid1.clone(),
                            value,
                        });
                    } else {
                        match okeep.get_next(oid1.clone()) {
                            Ok(bind) => vb.push(bind),
                            Err(_) => vb.push(VarBind {
                                name: oid1.clone(),
                                value: VarBindValue::EndOfMibView,
                            }),
                        }
                    }
                } else if insert_point >= oid_map.len() {
                    vb.push(VarBind {
                        name: roid.clone(),
                        value: VarBindValue::EndOfMibView,
                    });
                } else {
                    let oid1 = &oid_map.oid(insert_point).clone();
                    let last_keep = &mut oid_map.idx(insert_point);

                    if last_keep.is_scalar(oid1.clone()) {
                        match last_keep.get(oid1.clone()) {
                            Ok(value) => vb.push(VarBind {
                                name: oid1.clone(),
                                value,
                            }),
                            Err(e) => {
                                debug!("Error on scalar get {e:?}");
                                vb.push(VarBind {
                                    name: oid1.clone(),
                                    value: VarBindValue::Unspecified,
                                })
                            }
                        }
                    } else {
                        // Table
                        debug!("table case {insert_point}");
                        let next_res = last_keep.get_next(roid.clone());
                        match next_res {
                            Ok(next) => vb.push(next),
                            Err(bad) => match bad {
                                OidErr::OutOfRange => {
                                    debug!("Out of range {insert_point}");
                                    if insert_point == oid_map.len() {
                                        vb.push(VarBind {
                                            name: roid.clone(),
                                            value: VarBindValue::EndOfMibView,
                                        });
                                    } else {
                                        debug!("handle case following table end");
                                        let next_oid = oid_map.oid(insert_point).clone();
                                        let next_keep = &mut oid_map.idx(insert_point);
                                        if next_keep.is_scalar(next_oid.clone()) {
                                            let value = next_keep.get(next_oid.clone()).unwrap();
                                            vb.push(VarBind {
                                                name: next_oid.clone(),
                                                value,
                                            });
                                        } else {
                                            vb.push(next_keep.get_next(next_oid.clone()).unwrap());
                                        }
                                    }
                                }
                                OidErr::NoSuchInstance => {
                                    *error_index = vb_cnt;
                                    *error_status = Pdu::ERROR_STATUS_NO_ACCESS;
                                    vb.push(VarBind {
                                        name: roid,
                                        value: VarBindValue::NoSuchObject,
                                    });
                                }
                                OidErr::NoSuchName => {
                                    *error_index = vb_cnt;
                                    *error_status = Pdu::ERROR_STATUS_NO_SUCH_NAME;
                                    vb.push(VarBind {
                                        name: roid,
                                        value: VarBindValue::NoSuchObject,
                                    });
                                }
                                _ => {
                                    warn!("unexpected response from get_next {bad:?}")
                                }
                            },
                        }
                    }
                }
            }
            Ok(which) => {
                debug!("hit case {which}");
                if which == oid_map.len() - 1 {
                    debug!("End of oids, ");
                    // This should error and generate a report?
                    vb.push(VarBind {
                        name: roid.clone(),
                        value: VarBindValue::EndOfMibView,
                    });
                } else if oid_map.idx(which).is_scalar(roid.clone()) {
                    let next_oid: ObjectIdentifier = oid_map.oid(which + 1).clone();
                    let okeep = &mut oid_map.idx(which + 1);
                    if okeep.is_scalar(next_oid.clone()) {
                        let value_res = okeep.get(next_oid.clone());
                        match value_res {
                            Err(_) => vb.push(VarBind {
                                name: next_oid.clone(),
                                value: VarBindValue::Unspecified,
                            }),
                            Ok(value) => vb.push(VarBind {
                                name: next_oid.clone(),
                                value,
                            }),
                        }
                    } else {
                        vb.push(okeep.get_next(roid.clone()).unwrap());
                    };
                } else {
                    let okeep = &mut oid_map.idx(which);
                    debug!("Trying okeep");
                    let gn_res = okeep.get_next(roid.clone());
                    match gn_res {
                        Ok(nvb) => vb.push(nvb),
                        //FIXME More cases here - permissions, general error etc, not just end
                        Err(_) => {
                            vb.push(VarBind {
                                name: roid.clone(),
                                value: VarBindValue::EndOfMibView,
                            });
                        }
                    }
                }
            }
        }
    }

    fn getnext(
        &self,
        oid_map: &mut OidMap,
        r: GetNextRequest,
        vb: &mut Vec<VarBind>,
        perm: &Perm,
        flags: u8,
    ) -> (u32, u32, i32) {
        let mut error_status = Pdu::ERROR_STATUS_NO_ERROR;
        let mut error_index = 0u32;
        let request_id = r.0.request_id;
        for (vb_cnt, vbind) in r.0.variable_bindings.iter().enumerate() {
            let roid = vbind.name.clone();
            self.do_next(
                roid,
                oid_map,
                vb,
                &mut error_status,
                &mut error_index,
                vb_cnt.try_into().unwrap(),
                perm,
                flags,
            );
        }
        (error_status, error_index, request_id)
    }

    fn set(
        &self,
        oid_map: &mut OidMap,
        r: SetRequest,
        vb: &mut Vec<VarBind>,
        perm: &Perm,
        flags: u8,
    ) -> (u32, u32, i32) {
        let mut error_status = Pdu::ERROR_STATUS_NO_ERROR;
        let mut error_index = 0;
        let request_id = r.0.request_id;
        let mut vb_cnt = 0;
        for vbind in r.0.variable_bindings {
            let roid = vbind.name.clone();

            if !perm.check(flags, true, &roid) {
                error_status = Pdu::ERROR_STATUS_NO_ACCESS;
                error_index = vb_cnt;
                return (error_status, error_index, request_id);
            }
            let opt_set: Result<usize, usize> = oid_map.search(&roid);
            match opt_set {
                Err(insert_point) => {
                    debug!("Set miss case {insert_point}");
                    let okeep = &mut oid_map.idx(insert_point - 1);
                    if okeep.is_scalar(roid.clone()) {
                        debug!("Scalar set miss"); // This should error and generate a report?
                        error_status = Pdu::ERROR_STATUS_NO_SUCH_NAME;
                        error_index = vb_cnt;
                        vb.push(VarBind {
                            name: roid,
                            value: VarBindValue::NoSuchObject,
                        });
                        break;
                    } else {
                        debug!("Table set ");
                        let set_res = okeep.set(roid.clone(), vbind.value);
                        debug!("Table set {set_res:?}");
                        match set_res {
                            Ok(res) => vb.push(VarBind {
                                name: roid.clone(),
                                value: res,
                            }),
                            Err(_) => {
                                error_status = Pdu::ERROR_STATUS_NO_SUCH_NAME;
                                vb.push(VarBind {
                                    name: roid,
                                    value: VarBindValue::NoSuchObject,
                                });
                            }
                        }
                    }
                }
                Ok(which) => {
                    vb_cnt += 1;
                    let okeep = &mut oid_map.idx(which);
                    let set_result = (**okeep).set(roid.clone(), vbind.value.clone());
                    if let Err(OidErr::WrongType) = set_result {
                        error_status = Pdu::ERROR_STATUS_WRONG_TYPE;
                        vb.push(VarBind {
                            name: roid.clone(),
                            value: vbind.value,
                        });
                    } else {
                        let svalue = set_result.unwrap();
                        // Need to catch size, data type etc
                        vb.push(VarBind {
                            name: roid.clone(),
                            value: svalue,
                        });
                    }
                }
            }
        }
        (error_status, error_index, request_id)
    }

    fn bulk(
        &self,
        oid_map: &mut OidMap,
        r: GetBulkRequest,
        vb: &mut Vec<VarBind>,
        perm: &Perm,
        flags: u8,
    ) -> (u32, u32, i32) {
        let mut error_status = Pdu::ERROR_STATUS_NO_ERROR;
        let mut error_index = 0;
        let mut vb_cnt = 0u32;
        let request_id = r.0.request_id;
        let non_repeaters: usize = r.0.non_repeaters.try_into().unwrap();
        let max_repeats = r.0.max_repetitions;
        let mut rep_oids: Vec<ObjectIdentifier> = vec![];
        for (n, vbind) in r.0.variable_bindings.iter().enumerate() {
            let roid = vbind.name.clone();
            if n < non_repeaters {
                self.do_next(
                    roid,
                    oid_map,
                    vb,
                    &mut error_status,
                    &mut error_index,
                    vb_cnt,
                    perm,
                    flags,
                );
                vb_cnt += 1;
            } else {
                // construct repeater row
                debug!("Repeat {vbind:?}");
                rep_oids.push(vbind.name.clone());
            }
        }
        // Now do repeating rows
        for i in 0..max_repeats {
            let mut new_oids: Vec<ObjectIdentifier> = vec![];
            for roid in &rep_oids {
                self.do_next(
                    roid.clone(),
                    oid_map,
                    vb,
                    &mut error_status,
                    &mut error_index,
                    vb_cnt,
                    perm,
                    flags,
                );
                let last = vb.last().unwrap();
                new_oids.push(last.name.clone());
                vb_cnt += 1;
            }
            debug!("{i}th the repetition");
            for (n, oid) in new_oids.iter().enumerate() {
                rep_oids[n] = oid.clone();
            }
        }
        (error_status, error_index, request_id)
    }

    /// Process a Scoped PDU, returning an Option<Response>
    ///
    /// Returns None on unsupported PDU types, like BulkRequest
    ///
    /// When everything is supported, remove Option
    fn do_scoped_pdu(
        &self,
        flags: u8,
        opt_usr: Option<&usm::User>,
        scoped_pdu: ScopedPdu,
        oid_map: &mut OidMap,
    ) -> Option<Response> {
        //
        let mut skip_pdu = false;
        let mut vb: Vec<VarBind> = Vec::new();
        let mut error_status = Pdu::ERROR_STATUS_NO_ERROR;
        let mut error_index = 0;
        let mut request_id = 0;
        let _context_name = scoped_pdu.name;
        let perm = if let Some(user) = opt_usr {
            user.perm
        } else {
            return None;
        };

        match scoped_pdu.data {
            Pdus::GetRequest(r) => {
                (error_status, error_index, request_id) =
                    self.get(oid_map, r, &mut vb, perm, flags);
            }
            Pdus::GetNextRequest(r) => {
                (error_status, error_index, request_id) =
                    self.getnext(oid_map, r, &mut vb, perm, flags);
            }
            Pdus::SetRequest(r) => {
                (error_status, error_index, request_id) =
                    self.set(oid_map, r, &mut vb, perm, flags);
            }
            Pdus::GetBulkRequest(r) => {
                (error_status, error_index, request_id) =
                    self.bulk(oid_map, r, &mut vb, perm, flags);
                // Do BulkRequest once tables work properly
            }
            _ => skip_pdu = true,
        }
        if skip_pdu {
            None
        } else {
            let pdu = Pdu {
                request_id,
                error_index,
                error_status,
                variable_bindings: vb,
            };
            Some(Response(pdu))
        }
    }

    /// Send Message back to originator at addr
    fn send(&self, addr: SocketAddr, message: Message) {
        let buf_res = rasn::ber::encode(&message);
        match buf_res {
            Ok(buf) => {
                let _ = self.socket.send_to(&buf, addr);
            }
            Err(err) => error!("encodeError on returned Message{err:?}, dropping packet"),
        }
    }
    /// Main server loop entry point
    ///
    /// oid_map is Vec of tuples of (&ObjectIdentifier, &mut OidKeeper)
    ///
    /// This can be populated in any order, as it is sorted on the Oids before the loop starts.
    ///
    pub fn loop_forever(&mut self, oid_map: &mut OidMap, users: Vec<usm::User>) {
        let mut buf = [0; 65100];
        let mut opt_user: Option<&usm::User> = None;
        // Sort by oid, the lookups use binary search.
        oid_map.sort();
        loop {
            let recv_res = self.socket.recv_from(&mut buf);
            // If the socket read fails, there is nothing much we can do.
            if recv_res.is_err() {
                continue;
            }
            self.in_pkts += 1;
            let (amt, src) = recv_res.unwrap();

            // Redeclare `buf` as slice of the received data
            let buf = &mut buf[..amt];
            let decode_res: Result<Message, rasn::error::DecodeError> = rasn::ber::decode(buf);
            // Simply ignore packets that do not decode
            // In theory, should send decode error
            if decode_res.is_err() {
                self.decode_error_cnt += 1;
                continue;
            }
            let mut message: Message = decode_res.unwrap();
            let message_id = message.global_data.message_id.to_owned();
            let flags: u8 = *message.global_data.flags.first().unwrap();

            // Now do inner decode of security parameters
            let r_sp: Result<USMSecurityParameters, Box<dyn Display>> =
                message.decode_security_parameters(rasn::Codec::Ber);
            // Simply ignore packets that do not decode
            // In theory, should send decode error
            if r_sp.is_err() {
                continue;
            }
            let usp: USMSecurityParameters = r_sp.ok().expect("Errors caught above");
            // Check the authentication
            if flags & 1 == 1 {
                // FIXME
                // Both these cases should send Authentication Failure, rather
                // than silently dropping the packet. Maybe some
                // other auth types have different lengths, so logic
                // may be more complex. Probably have to look up user,
                // and take authentication length from the required method.
                if usp.authentication_parameters.len() != 12 {
                    warn!("Authentication parameters must be 12 bytes");
                    continue;
                }
                opt_user = Self::lookup_user(usp.user_name.to_vec(), &users);
                if self.wrong_auth(&mut message, opt_user, usp.clone()) {
                    warn!("Wrong auth, dropping");
                    continue;
                }
            }

            match message.scoped_data {
                ScopedPduData::CleartextPdu(scoped_pdu) => {
                    // FIXME Add extra conditions here on engine_id discovery
                    if scoped_pdu.engine_id.to_vec() == b"" {
                        // Return EngineId if manager does not know it yet.
                        // This has to be in clear, as engine_id is used in the
                        // encryption.
                        if let Pdus::GetRequest(r) = scoped_pdu.data {
                            let request_id = r.0.request_id;
                            self.unknown_engine_ids += 1;
                            self.send(src, self.id_response(request_id, message_id));
                        }
                        continue;
                    }
                    let resp_opt: Option<Response> =
                        self.do_scoped_pdu(flags, opt_user, scoped_pdu, oid_map);
                    if resp_opt.is_none() {
                        continue;
                    }
                    let resp = resp_opt.unwrap();
                    let mut out_message = self.prepare_back(message_id, resp, None, usp);
                    out_message.global_data.flags = message.global_data.flags;
                    if flags & 1 == 1 {
                        self.set_auth(&mut out_message, opt_user);
                    }
                    self.send(src, out_message);
                }
                ScopedPduData::EncryptedPdu(enc_octs) => {
                    let key = &opt_user.unwrap().priv_key;
                    let buf2: Vec<u8> = privacy::decrypt(&mut enc_octs.to_vec(), usp.clone(), key);
                    let pdu_decode_res: Result<ScopedPdu, rasn::error::DecodeError> =
                        rasn::ber::decode(&buf2);
                    if pdu_decode_res.is_err() {
                        // Should return decode error
                        warn!("Decode error {pdu_decode_res:?}");
                        continue;
                    }
                    let scoped_pdu: ScopedPdu = pdu_decode_res.unwrap();
                    let resp_opt: Option<Response> =
                        self.do_scoped_pdu(flags, opt_user, scoped_pdu, oid_map);
                    if resp_opt.is_none() {
                        warn!("No response, discarding");
                        continue;
                    }
                    let resp = resp_opt.unwrap();
                    let mut out_message =
                        self.prepare_back(message_id, resp, opt_user, usp.clone());
                    out_message.global_data.flags = message.global_data.flags;
                    if flags & 1 == 1 {
                        self.set_auth(&mut out_message, opt_user);
                    }
                    self.send(src, out_message);
                }
            }
        }
    }

    fn set_auth(&self, message: &mut Message, opt_usr: Option<&usm::User>) -> Vec<u8> {
        let r_sp: Result<USMSecurityParameters, Box<dyn Display>> =
            message.decode_security_parameters(rasn::Codec::Ber);
        if r_sp.is_err() {
            return vec![];
        }
        let mut usp: USMSecurityParameters = r_sp.ok().expect("Errors caught above");
        usp.authentication_parameters = Z12;
        let _ = message.encode_security_parameters(rasn::Codec::Ber, &usp);
        let buf = rasn::ber::encode(message).unwrap();
        if opt_usr.is_none() {
            return vec![];
        }
        let usr = opt_usr.unwrap();
        let auth = usr.auth_from_bytes(&buf);
        usp.authentication_parameters = OctetString::copy_from_slice(&auth);
        let _ = message.encode_security_parameters(rasn::Codec::Ber, &usp);
        auth
    }

    /// Return true if the auth is wrong
    fn wrong_auth(
        &self,
        message: &mut Message,
        opt_usr: Option<&usm::User>,
        usp: USMSecurityParameters,
    ) -> bool {
        if opt_usr.is_none() {
            warn!("User is none");
            return true;
        }
        let hmac = usp.authentication_parameters.clone().to_vec();
        let our_hmac = self.set_auth(message, opt_usr);
        // Actually check the auth
        if hmac != our_hmac {
            debug!("Message hmac {hmac:?} ours {our_hmac:?} ");
            return true;
        }
        false
    }

    /// Lookup user by name.
    fn lookup_user<'a>(name: Vec<u8>, users: &'a Vec<usm::User>) -> Option<&'a usm::User<'a>> {
        for user in users {
            let uname = user.name.clone();
            if uname == name {
                return Some(user);
            }
        }
        warn!("Name doesn't match");
        None
    }
}
