mod engine_id;
pub mod keeper;
mod privacy;
mod usm;

pub mod snmp_agent {

    pub use crate::engine_id::snmp_engine_id;
    use crate::keeper::oid_keep::OidKeeper;
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

    /// Type used to hold mapping between ObjectIdentifiers and instances
    /// that support OidKeep
    pub type OidMap<'a, T> = Vec<(&'a ObjectIdentifier, &'a mut T)>;

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
        /// eid is the engine id. 
        /// addr_str is the address to listen on - often "0.0.0.0:161" can be a good choice
        /// But systems with multiple interfaces (like a firewall) might only listen on an internal
        /// address.
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

        /// Internal method for supporting engine ID discovery
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

        /// Process a Scoped PDU, returning a Response
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
                        let opt_get: Result<usize, usize> =
                            oid_map.binary_search_by(|a| a.0.cmp(&roid));
                        match opt_get {
                            Err(_ew) => {
                                // This should error and generate a report?
                                error_status = Pdu::ERROR_STATUS_NO_SUCH_NAME;
                                vb.push(VarBind {
                                    name: roid,
                                    value: VarBindValue::NoSuchObject,
                                });
                                error_index = vb_cnt;
                            }
                            Ok(which) => {
                                vb_cnt += 1;
                                let okeep = &oid_map[which].1;
                                vb.push(VarBind {
                                    name: roid.clone(),
                                    value: okeep.get(roid.clone()).expect("Should work"),
                                });
                            }
                        }
                    }
                }
                Pdus::GetNextRequest(r) => {
                    request_id = r.0.request_id;
                    for vbind in r.0.variable_bindings {
                        let roid = vbind.name.clone();
                        let opt_get: Result<usize, usize> =
                            oid_map.binary_search_by(|a| a.0.cmp(&roid));
                        match opt_get {
                            Err(insert_point) => {
                                if insert_point == 0 {  // Off the front of our range.
                                    error_index = vb_cnt;
                                    error_status = Pdu::ERROR_STATUS_NO_SUCH_NAME;
                                    vb.push(VarBind {
                                        name: roid,
                                        value: VarBindValue::NoSuchObject,
                                    });
                                } else {
                                    if insert_point == oid_map.len() {
                                        vb.push(VarBind {
                                            name: roid.clone(),
                                            value: VarBindValue::EndOfMibView,
                                        });
                                    } else {
                                        let last_keep = &oid_map[insert_point - 1].1;
                                        if last_keep.is_scalar() {
                                            error_index = vb_cnt;
                                            error_status = Pdu::ERROR_STATUS_NO_SUCH_NAME;
                                            vb.push(VarBind {
                                                name: roid,
                                                value: VarBindValue::NoSuchObject,
                                            });
                                        } else {
                                           ///////////////// vb.push()
                                        }
                                    }
                                }
                                
                                
                            }
                            Ok(which) => {
                                vb_cnt += 1;
                                if which == oid_map.len() {
                                    // This should error and generate a report?
                                    vb.push(VarBind {
                                        name: roid,
                                        value: VarBindValue::EndOfMibView,
                                    });
                                } else {
                                    let next_oid: ObjectIdentifier = oid_map[which + 1].0.clone();
                                    let okeep = &oid_map[which + 1].1;
                                    vb.push(VarBind {
                                        name: next_oid.clone(),
                                        value: okeep.get(next_oid.clone()).unwrap(),
                                    });
                                }
                            }
                        }
                    }
                }
                Pdus::SetRequest(r) => {
                    request_id = r.0.request_id;
                    for vbind in r.0.variable_bindings {
                        let roid = vbind.name.clone();
                        let opt_get: Result<usize, usize> =
                            oid_map.binary_search_by(|a| a.0.cmp(&roid));
                        match opt_get {
                            Err(_ew) => {
                                // This should error and generate a report?
                                error_status = Pdu::ERROR_STATUS_NO_SUCH_NAME;
                                error_index = vb_cnt;
                                vb.push(VarBind {
                                    name: roid,
                                    value: VarBindValue::NoSuchObject,
                                });
                                break;
                            }
                            Ok(which) => {
                                vb_cnt += 1;
                                let noid: ObjectIdentifier = oid_map[which].0.clone();
                                let okeep: &mut &mut T = &mut oid_map[which].1;
                                let set_result = (**okeep).set(noid.clone(), vbind.value.clone());
                                if set_result.is_err() {
                                    error_status = Pdu::ERROR_STATUS_WRONG_TYPE;
                                    vb.push(VarBind {
                                        name: noid.clone(),
                                        value: vbind.value,
                                    });
                                } else {
                                    let svalue = set_result.unwrap();
                                    // Need to catch size, data type etc
                                    vb.push(VarBind {
                                        name: noid.clone(),
                                        value: svalue,
                                    });
                                }
                            }
                        }
                    }
                }
                // Do BulkRequest once tables work properly
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
        /// oid_map is Vec of tuples of & ObjectIdentifier, &mut OidKeeper
        ///
        /// This can be populated in any order, as it is sorted before the loop starts.
        ///
        pub fn loop_forever<T: OidKeeper>(&mut self, oid_map: &mut OidMap<T>) {
            let mut buf = [0; 65100];
            let mut opt_user: Option<&usm::User> = None;
            // Sort by oid, the lookups use binary search.
            oid_map.sort_by(|a, b| a.0.cmp(b.0));
            loop {
                let recv_res = self.socket.recv_from(&mut buf);
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

                /* */
                let r_sp: Result<USMSecurityParameters, Box<dyn Display>> =
                    message.decode_security_parameters(rasn::Codec::Ber);
                // Simply ignore packets that do not decode
                // In theory, should send decode error
                if r_sp.is_err() {
                    continue;
                }
                let usp: USMSecurityParameters = r_sp.ok().expect("Errors caught above");
                if flags & 1 == 1 {
                    // Both these cases should send Authentication Failure
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
                        // Add extra conditions here
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
