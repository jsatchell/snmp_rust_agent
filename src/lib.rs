mod usm;

pub mod snmp_agent {

    use rasn;
    use rasn::types::{Integer, ObjectIdentifier, OctetString};
    use rasn_smi::v2::SimpleSyntax;
    use rasn_snmp::v2::{ObjectSyntax, Pdu, Report, VarBind};
    use rasn_snmp::v3::VarBindValue;
    use rasn_snmp::v3::{HeaderData, Message, Pdus, ScopedPdu, USMSecurityParameters};
    use rasn_snmp::v3::{Response, ScopedPduData};
    use std::collections::BTreeMap;
    use std::fmt::Display;
    use std::fs::{read_to_string, write};
    use std::net::SocketAddr;
    use std::net::UdpSocket;
    use std::str::FromStr;
    use std::time::Instant;

    use crate::usm;

    const BOOTCNT_FILENAME: &str = "boot-cnt.txt";
    const B12: [u8; 12] = [0; 12];
    const Z12: OctetString = OctetString::from_static(&B12);

    pub fn always_42() -> VarBindValue {
        VarBindValue::Value(ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(
            42,
        ))))
    }

    pub fn always_17() -> VarBindValue {
        VarBindValue::Value(ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(
            17,
        ))))
    }

    /// Send Message back to originator at addr
    fn send(socket: &UdpSocket, addr: SocketAddr, message: Message) {
        let buf = rasn::ber::encode(&message).unwrap();
        // println!("outgoing buf is {buf:?}");
        let _ = socket.send_to(&buf, &addr);
        ()
    }

    /// Get the boot count from non-volatile storage, creating file if it does not exist.
    /// Panic if the file cannot be parsed, as that indicates tampering or hardware failure.
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
    pub struct Agent {
        pub oid_map: BTreeMap<ObjectIdentifier, fn() -> VarBindValue>,
        socket: UdpSocket,
        engine_id: OctetString,
        users: Vec<usm::User>,
        start_time: Instant,
        boots: isize,
    }

    impl Agent {
        pub fn build(eid: OctetString, addr_str: &str) -> Agent {
            let sock = UdpSocket::bind(addr_str).expect("Couldn't bind to address");
            let users = usm::load_users();
            Agent {
                oid_map: BTreeMap::new(),
                socket: sock,
                engine_id: eid,
                users: users,
                start_time: Instant::now(),
                boots: get_increment_boot_cnt(),
            }
        }

        pub fn insert(&mut self, oid: ObjectIdentifier, getter: fn() -> VarBindValue) {
            self.oid_map.insert(oid, getter);
        }

        fn id_resp(&self, request_id: i32, message_id: Integer) -> Message {
            let vb: Vec<VarBind> = vec![VarBind {
                name: ObjectIdentifier::new_unchecked(
                    vec![1, 3, 6, 1, 6, 3, 15, 1, 1, 4].into(),
                ),
                value: VarBindValue::Value(ObjectSyntax::Simple(SimpleSyntax::Integer(
                    Integer::from(4),
                ))),
            }];

            let pdu = Pdu {
                request_id: request_id,
                error_index: 0,
                error_status: 0,
                variable_bindings: vb,
            };
            let report: Report = Report(pdu);
            let head = HeaderData {
                flags: OctetString::from_static(b"\x00"),
                message_id: message_id,
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
                user_name: OctetString::from_static(b""),
                authentication_parameters: OctetString::from_static(b""),
                privacy_parameters: OctetString::from_static(b""),
            };
            let mut message: Message = Message {
                version: Integer::Primitive(3),
                global_data: head,
                scoped_data: spd,
                security_parameters: OctetString::from_static(b""),
            };
            _ = message.encode_security_parameters(rasn::Codec::Ber, &usm);
            println!("Out message {message:?}");
            message
        }

        fn prepare_back(&self, message_id: Integer, resp: Response) -> Message {
            // Return message with matching ids etc.
            let head = HeaderData {
                flags: OctetString::from_static(b"\x00"),
                message_id: message_id,
                max_size: Integer::from(65000),
                security_model: Integer::from(3),
            };
            let scpd: ScopedPdu = ScopedPdu {
                engine_id: self.engine_id.clone(),
                name: OctetString::from_static(b""),
                data: Pdus::Response(resp),
            };
            let spd: ScopedPduData = ScopedPduData::CleartextPdu(scpd);
            let mut output: Message = Message {
                version: Integer::Primitive(3),
                global_data: head,
                scoped_data: spd,
                security_parameters: OctetString::from_static(b""),
            };
            let usm: USMSecurityParameters = USMSecurityParameters {
                authoritative_engine_boots: Integer::Primitive(5),
                authoritative_engine_id: self.engine_id.clone(),
                authoritative_engine_time: Integer::Primitive(11),
                user_name: OctetString::from_static(b"myv3user"),
                authentication_parameters: OctetString::from_static(b""),
                privacy_parameters: OctetString::from_static(b""),
            };
            _ = output.encode_security_parameters(rasn::Codec::Ber, &usm);
            output
        }

        fn do_scoped_pdu(&self, scoped_pdu: ScopedPdu, message_id: Integer) -> Option<Message> {
            //
            match scoped_pdu.data {
                Pdus::GetRequest(r) => {
                    let request_id = r.0.request_id;
                    if scoped_pdu.engine_id.to_vec() == b"" {
                        return Some(self.id_resp(request_id, message_id));
                    } else {
                        let mut vb: Vec<VarBind> = Vec::new();
                        for vbind in r.0.variable_bindings {
                            let roid = vbind.name.clone();
                            let opt_get = self.oid_map.get(&roid);
                            match opt_get {
                                None => {
                                    // This should error and generate a report?
                                    vb.push(VarBind {
                                        name: roid,
                                        value: always_17(),
                                    });
                                }
                                Some(get) => {
                                    vb.push(VarBind {
                                        name: roid,
                                        value: get(),
                                    });
                                }
                            }
                        }

                        let pdu = Pdu {
                            request_id: request_id,
                            error_index: 0,
                            error_status: 0,
                            variable_bindings: vb,
                        };
                        println!("Should build a Response instead!");
                        let resp = Response(pdu);
                        return Some(self.prepare_back(message_id, resp));
                    }
                }
                Pdus::GetNextRequest(r) => {} //let request_id = r.0.request_id},
                Pdus::SetRequest(r) => {}     //et request_id = r.0.request_id},
                _ => {}
            }
            None
        }

        pub fn loop_forever(&mut self) {
            let mut buf = [0; 65100];
            let mut opt_user:Option<&usm::User> = None;
            loop {
                let recv_res = self.socket.recv_from(&mut buf);
                if recv_res.is_err() {
                    continue;
                }
                let (amt, src) = recv_res.unwrap();

                // Redeclare `buf` as slice of the received data
                let buf = &mut buf[..amt];
                let decode_res: Result<Message, rasn::error::DecodeError> = rasn::ber::decode(&buf);
                if decode_res.is_err() {
                    continue;
                }
                let mut message: Message = decode_res.unwrap();
                let message_id = message.global_data.message_id.to_owned();
                let flags: u8 = *message.global_data.flags.first().unwrap();

                /* */
                let r_sp: Result<USMSecurityParameters, Box<dyn Display>> =
                    message.decode_security_parameters(rasn::Codec::Ber);
                if r_sp.is_err() {
                    continue;
                }
                let usp: USMSecurityParameters = r_sp.ok().expect("Errors caught above");
                println!("usp {usp:?} flags {flags}");
                if flags & 1 == 1 {
                    if usp.authentication_parameters.len() != 12 {
                        println!("Authentication parameters must be 12 bytes");
                        continue;
                    }
                    opt_user = self.lookup_user(usp.user_name.to_vec());
                    if self.wrong_auth(&mut message, opt_user, usp) {
                        println!("Wrong auth, dropping");
                        continue;
                    }
                }

                match message.scoped_data {
                    ScopedPduData::CleartextPdu(scoped_pdu) => {
                        let mess_opt: Option<Message> = self.do_scoped_pdu(scoped_pdu, message_id);
                        if mess_opt.is_none() {
                            continue;
                        }
                        let mut out_message = mess_opt.unwrap();
                        out_message.global_data.flags = message.global_data.flags;
                        if flags & 1 == 1 {
                            self.set_auth(&mut out_message, opt_user);
                        }
                        send(&self.socket, src, out_message);
                    }
                    ScopedPduData::EncryptedPdu(_enc_oct) => {
                        println!("Ignoring encrypted")
                    }
                }
            }
        }

        fn set_auth(&self,
            message: &mut Message,
            opt_usr: Option<&usm::User>) -> Vec<u8> {
            let r_sp: Result<USMSecurityParameters, Box<dyn Display>> =
            message.decode_security_parameters(rasn::Codec::Ber);
            if r_sp.is_err() {
               return vec![];
            }
            let mut usp: USMSecurityParameters = r_sp.ok().expect("Errors caught above");
            usp.authentication_parameters = Z12;
            let _ = message.encode_security_parameters(rasn::Codec::Ber, &usp);
            let buf = rasn::ber::encode(message).unwrap();
            if opt_usr.is_none() {return vec![]}
            let usr = opt_usr.unwrap();
            let auth = usr.auth_from_bytes(&buf);
            println!("Auth set to {auth:?}");
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
            println!("Checking auth");
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
            println!("Hmac-sha1-96 matches!!!!");
            false
        }

        fn lookup_user(&self, name: Vec<u8>) -> Option<&usm::User> {
            for user in &self.users {
                let uname = user.name.clone();
                println!("Trying {uname:?} {name:?}");
                if uname == name {
                    return Some(user);
                }
            }
            println!("Name doesn't match");
            None
        }
    }
}
