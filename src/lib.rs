mod engine_id;
pub mod keeper;
pub mod oidmap;
mod privacy;
mod usm;

pub mod snmp_agent {

    pub use crate::engine_id::snmp_engine_id;
    use crate::keeper::oid_keep::{OidErr, OidKeeper};
    use crate::oidmap::OidMap;
    use crate::privacy;
    use crate::usm;
    use rasn;
    use rasn::types::{Integer, ObjectIdentifier, OctetString};
    use rasn_smi::v2::{ObjectSyntax, SimpleSyntax};
    use rasn_snmp::v2::{Pdu, Report, VarBind};
    use rasn_snmp::v3::VarBindValue;
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
        users: Vec<usm::User>,
        start_time: Instant,
        boots: isize,
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
            let users = usm::load_users();
            Agent {
                socket: sock,
                engine_id: eid,
                users,
                start_time: Instant::now(),
                boots: get_increment_boot_cnt(),
            }
        }

        /// Internal method for supporting engine ID discovery by managers
        fn id_resp(&self, request_id: i32, message_id: Integer) -> Message {
            let vb: Vec<VarBind> = vec![VarBind {
                name: ObjectIdentifier::new_unchecked(vec![1, 3, 6, 1, 6, 3, 15, 1, 1, 4].into()),
                value: VarBindValue::Value(ObjectSyntax::Simple(SimpleSyntax::Integer(
                    Integer::from(4),
                ))),
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
                authoritative_engine_boots: Integer::Primitive(self.boots),
                authoritative_engine_id: self.engine_id.clone(),
                authoritative_engine_time: Integer::Primitive(run_time),
                user_name: ZB,
                authentication_parameters: ZB,
                privacy_parameters: ZB,
            };
            let mut message: Message = Message {
                version: Integer::Primitive(3),
                global_data: head,
                scoped_data: spd,
                security_parameters: ZB,
            };
            _ = message.encode_security_parameters(rasn::Codec::Ber, &usm);
            message
        }

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
            let mut spd: ScopedPduData = ScopedPduData::CleartextPdu(scpd);
            let run_time: isize = self.start_time.elapsed().as_secs().try_into().unwrap();
            let mut usm: USMSecurityParameters = USMSecurityParameters {
                authoritative_engine_boots: Integer::Primitive(self.boots),
                authoritative_engine_id: self.engine_id.clone(),
                authoritative_engine_time: Integer::Primitive(run_time),
                user_name: OctetString::from_static(b"myv3user"),
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
                version: Integer::Primitive(3),
                global_data: head,
                scoped_data: spd,
                security_parameters: ZB,
            };

            _ = output.encode_security_parameters(rasn::Codec::Ber, &usm);
            output
        }

        /// Process a Scoped PDU, returning an Option<Response>
        ///
        /// Returns None on unsupported PDU types, like BulkRequest
        ///
        /// When everything is supported, remove Option
        fn do_scoped_pdu<T: OidKeeper>(
            &self,
            scoped_pdu: ScopedPdu,
            oid_map: &mut OidMap<T>,
        ) -> Option<Response> {
            //
            let mut skip_pdu = false;
            let mut vb: Vec<VarBind> = Vec::new();
            let mut error_status = Pdu::ERROR_STATUS_NO_ERROR;
            let mut error_index = 0;
            let mut request_id = 0;
            let mut vb_cnt = 0;
            match scoped_pdu.data {
                Pdus::GetRequest(r) => {
                    request_id = r.0.request_id;
                    for vbind in r.0.variable_bindings {
                        let roid = vbind.name.clone();
                        let opt_get: Result<usize, usize> = oid_map.search(&roid);
                        match opt_get {
                            Err(insert_point) => {
                                //
                                // This should error and generate a report?
                                println!("Get miss case {insert_point}");
                                let okeep = &oid_map.idx(insert_point - 1);
                                if okeep.is_scalar() {
                                    println!("Scalar get ");
                                    error_status = Pdu::ERROR_STATUS_NO_SUCH_NAME;
                                    vb.push(VarBind {
                                        name: roid,
                                        value: VarBindValue::NoSuchObject,
                                    });
                                    error_index = vb_cnt;
                                } else {
                                    println!("Table get ");
                                    let get_res = okeep.get(roid.clone());
                                    println!("Table get {get_res:?}");
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
                                let okeep = &oid_map.idx(which);
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
                }
                Pdus::GetNextRequest(r) => {
                    request_id = r.0.request_id;
                    for vbind in r.0.variable_bindings {
                        let roid = vbind.name.clone();
                        let opt_get: Result<usize, usize> = oid_map.search(&roid);
                        match opt_get {
                            Err(insert_point) => {
                                println!("Get next miss case {insert_point}");
                                if insert_point == 0 {
                                    // Off the front of our range.
                                    error_index = vb_cnt;
                                    error_status = Pdu::ERROR_STATUS_NO_SUCH_NAME;
                                    vb.push(VarBind {
                                        name: roid,
                                        value: VarBindValue::NoSuchObject,
                                    });
                                } else if insert_point == oid_map.len() {
                                    vb.push(VarBind {
                                        name: roid.clone(),
                                        value: VarBindValue::EndOfMibView,
                                    });
                                } else {
                                    let last_keep = &oid_map.idx(insert_point - 1);
                                    if last_keep.is_scalar() {
                                        error_index = vb_cnt;
                                        error_status = Pdu::ERROR_STATUS_NO_SUCH_NAME;
                                        vb.push(VarBind {
                                            name: roid,
                                            value: VarBindValue::NoSuchObject,
                                        });
                                    } else {
                                        // Table
                                        println!("table case {insert_point}");
                                        let next_res = last_keep.get_next(roid.clone());
                                        if let Ok(next) = next_res {
                                            vb.push(next);
                                        } else if insert_point == oid_map.len() - 1 {
                                            vb.push(VarBind {
                                                name: roid.clone(),
                                                value: VarBindValue::EndOfMibView,
                                            });
                                        } else {
                                            error_index = vb_cnt;
                                            error_status = Pdu::ERROR_STATUS_NO_SUCH_NAME;
                                            vb.push(VarBind {
                                                name: roid,
                                                value: VarBindValue::NoSuchObject,
                                            });
                                        }

                                        ///////////////// vb.push()
                                    }
                                }
                            }
                            Ok(which) => {
                                println!("hit case {which}");
                                vb_cnt += 1;
                                if which == oid_map.len() - 1 {
                                    println!("End of oids, ");
                                    // This should error and generate a report?
                                    vb.push(VarBind {
                                        name: roid.clone(),
                                        value: VarBindValue::EndOfMibView,
                                    });
                                } else if oid_map.idx(which).is_scalar() {
                                    let next_oid: ObjectIdentifier = oid_map.oid(which + 1).clone();
                                    let okeep = &oid_map.idx(which + 1);
                                    if okeep.is_scalar() {
                                        vb.push(VarBind {
                                            name: next_oid.clone(),
                                            value: okeep.get(next_oid.clone()).unwrap(),
                                        });
                                    } else {
                                        vb.push(okeep.get_next(roid.clone()).unwrap());
                                    };
                                } else {
                                    let okeep = &oid_map.idx(which);
                                    println!("Trying okeep");
                                    let gn_res = okeep.get_next(roid.clone());
                                    match gn_res {
                                        Ok(nvb) => vb.push(nvb),
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
                }
                Pdus::SetRequest(r) => {
                    // FIXME this is scalar only!
                    request_id = r.0.request_id;
                    for vbind in r.0.variable_bindings {
                        let roid = vbind.name.clone();
                        let opt_set: Result<usize, usize> = oid_map.search(&roid);
                        match opt_set {
                            Err(insert_point) => {
                                println!("Set miss case {insert_point}");
                                let okeep = &mut oid_map.idx(insert_point - 1);
                                if okeep.is_scalar() {
                                    println!("Scalar set miss"); // This should error and generate a report?
                                    error_status = Pdu::ERROR_STATUS_NO_SUCH_NAME;
                                    error_index = vb_cnt;
                                    vb.push(VarBind {
                                        name: roid,
                                        value: VarBindValue::NoSuchObject,
                                    });
                                    break;
                                } else {
                                    println!("Table set ");
                                    let set_res = okeep.set(roid.clone(), vbind.value);
                                    println!("Table set {set_res:?}");
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
                                // let noid: ObjectIdentifier = oid_map.oid(which).clone();
                                let okeep: &mut &mut T = &mut oid_map.idx(which);
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
                }
                Pdus::GetBulkRequest(r) => {
                    // Do BulkRequest once tables work properly
                    request_id = r.0.request_id;
                    let non_repeaters: usize = r.0.non_repeaters.try_into().unwrap();
                    let _max_repeats = r.0.max_repetitions;
                    for (n, vbind) in r.0.variable_bindings.iter().enumerate() {
                        if n < non_repeaters {
                            println!("Non rep {vbind:?}");
                        } else {
                            println!("Repeat {vbind:?}");
                        }
                    }
                    skip_pdu = true
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
            let buf = rasn::ber::encode(&message).unwrap();
            let _ = self.socket.send_to(&buf, addr);
        }
        /// Main server loop entry point
        ///
        /// oid_map is Vec of tuples of (&ObjectIdentifier, &mut OidKeeper)
        ///
        /// This can be populated in any order, as it is sorted on the Oids before the loop starts.
        ///
        pub fn loop_forever<T: OidKeeper>(&mut self, oid_map: &mut OidMap<T>) {
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
                let (amt, src) = recv_res.unwrap();

                // Redeclare `buf` as slice of the received data
                let buf = &mut buf[..amt];
                let decode_res: Result<Message, rasn::error::DecodeError> = rasn::ber::decode(buf);
                // Simply ignore packets that do not decode
                // In theory, should send decode error
                if decode_res.is_err() {
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
                if flags & 1 == 1 {
                    // FIXME
                    // Both these cases should send Authentication Failure, rather
                    // than silently dropping the packet
                    if usp.authentication_parameters.len() != 12 {
                        println!("Authentication parameters must be 12 bytes");
                        continue;
                    }
                    opt_user = self.lookup_user(usp.user_name.to_vec());
                    if self.wrong_auth(&mut message, opt_user, usp.clone()) {
                        println!("Wrong auth, dropping");
                        continue;
                    }
                }

                match message.scoped_data {
                    ScopedPduData::CleartextPdu(scoped_pdu) => {
                        // FIXME Add extra conditions here on engine_id discovery
                        if scoped_pdu.engine_id.to_vec() == b"" {
                            if let Pdus::GetRequest(r) = scoped_pdu.data {
                                let request_id = r.0.request_id;
                                self.send(src, self.id_resp(request_id, message_id));
                            }
                            continue;
                        }
                        let resp_opt: Option<Response> = self.do_scoped_pdu(scoped_pdu, oid_map);
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
                        let buf2: Vec<u8> =
                            privacy::decrypt(&mut enc_octs.to_vec(), usp.clone(), key);
                        let pdu_decode_res: Result<ScopedPdu, rasn::error::DecodeError> =
                            rasn::ber::decode(&buf2);
                        if pdu_decode_res.is_err() {
                            println!("Decode error {pdu_decode_res:?}");
                            continue;
                        }
                        let scoped_pdu: ScopedPdu = pdu_decode_res.unwrap();
                        let resp_opt: Option<Response> = self.do_scoped_pdu(scoped_pdu, oid_map);
                        if resp_opt.is_none() {
                            println!("No response, discarding");
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

        fn wrong_auth(
            &self,
            message: &mut Message,
            opt_usr: Option<&usm::User>,
            usp: USMSecurityParameters,
        ) -> bool {
            if opt_usr.is_none() {
                println!("User is none");
                return true;
            }
            let hmac = usp.authentication_parameters.clone().to_vec();
            let our_hmac = self.set_auth(message, opt_usr);
            // Actually check the auth?
            if hmac != our_hmac {
                println!("Message hmac {hmac:?} ours {our_hmac:?} ");
                return true;
            }
            false
        }

        /// Lookup user by name.
        fn lookup_user(&self, name: Vec<u8>) -> Option<&usm::User> {
            for user in &self.users {
                let uname = user.name.clone();
                if uname == name {
                    return Some(user);
                }
            }
            println!("Name doesn't match");
            None
        }
    }
}
