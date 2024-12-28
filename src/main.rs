use rasn;
use rasn::types::{Integer, OctetString};
use rasn_smi;
use rasn_smi::v2::Integer32;
use rasn_snmp::v2::{ObjectSyntax, Pdu, Report, VarBind};
use rasn_snmp::v3::{HeaderData, Message, Pdus, ScopedPdu, USMSecurityParameters};
use rasn_snmp::v3::{Response, ScopedPduData};
use std::fmt::Display;
use std::net::SocketAddr;
use std::net::UdpSocket;

//Change this to match your organisation's IANA registartion, This example
// uses the "dynamic" MAC address scheme, but many other name systems work.
static ENGINESTR: &[u8; 11] = b"\x80\x00\x4e\x2c\x03\x34\x48\xed\x2d\xe2\x88";

fn unpack(data: &[u8]) -> Message {
    ///  Decode SNMPv3 message in data containing a SNMPv3 PDU.
    let message: Message = rasn::ber::decode(data).unwrap();
    let r_sp: Result<USMSecurityParameters, Box<dyn Display>> =
        message.decode_security_parameters(rasn::Codec::Ber);
    match r_sp {
        Ok(s) => {
            println!("Incoming sec {s:?}")
        }
        Err(e) => {
            println!("{e}")
        }
    }
    {
        let sdat: &ScopedPduData = &message.scoped_data;
        println!("Incoming PDUs {sdat:?}");
    }
    message
}

fn id_resp(request_id: i32, message_id: Integer, _req_engine: OctetString) -> Message {
    let vb: Vec<VarBind> = vec![VarBind {
        name: rasn::types::ObjectIdentifier::new_unchecked(
            vec![1, 3, 6, 1, 6, 3, 15, 1, 1, 4].into(),
        ),
        value: rasn_snmp::v3::VarBindValue::Value(ObjectSyntax::Simple(
            rasn_smi::v2::SimpleSyntax::Integer(rasn::types::Integer::Primitive(4)),
        )),
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
        engine_id: OctetString::from_static(ENGINESTR),
        name: OctetString::from_static(b"test"),
        data: Pdus::Report(report),
    };
    let spd: ScopedPduData = ScopedPduData::CleartextPdu(scpd);
    let usm: USMSecurityParameters = USMSecurityParameters {
        authoritative_engine_boots: rasn::types::Integer::Primitive(5),
        authoritative_engine_id: OctetString::from_static(ENGINESTR),
        authoritative_engine_time: rasn::types::Integer::Primitive(11),
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

fn send(socket: &UdpSocket, addr: SocketAddr, message: Message) {
    let buf = rasn::ber::encode(&message).unwrap();
    // println!("outgoing buf is {buf:?}");
    let _ = socket.send_to(&buf, &addr);
    ()
}

fn prepare_back(message_id: Integer, resp: Response) -> Message {
    // Return message with matching ids etc.
    let head = HeaderData {
        flags: OctetString::from_static(b"\x00"),
        message_id: message_id,
        max_size: Integer::from(65000),
        security_model: Integer::from(3),
    };
    let scpd: ScopedPdu = ScopedPdu {
        engine_id: OctetString::from_static(ENGINESTR),
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
        authoritative_engine_boots: rasn::types::Integer::Primitive(5),
        authoritative_engine_id: OctetString::from_static(ENGINESTR),
        authoritative_engine_time: rasn::types::Integer::Primitive(11),
        user_name: OctetString::from_static(b"myv3user"),
        authentication_parameters: OctetString::from_static(b""),
        privacy_parameters: OctetString::from_static(b""),
    };
    _ = output.encode_security_parameters(rasn::Codec::Ber, &usm);
    output
}

fn do_scoped_pdu(
    scoped_pdu: ScopedPdu,
    socket: &UdpSocket,
    message_id: Integer,
    src: SocketAddr,
) -> () {
    //
    match scoped_pdu.data {
        Pdus::GetRequest(r) => {
            let request_id = r.0.request_id;
            if scoped_pdu.engine_id.to_vec() == b"" {
                let bm = id_resp(request_id, message_id, scoped_pdu.engine_id);
                send(&socket, src, bm)
            } else {
                let ib = r.0.variable_bindings;
                let roid = ib[0].name.clone();
                let vb: Vec<VarBind> = vec![VarBind {
                    name: roid,
                    value: rasn_snmp::v3::VarBindValue::Value(ObjectSyntax::Simple(
                        rasn_smi::v2::SimpleSyntax::Integer(rasn::types::Integer::Primitive(42)),
                    )),
                }];

                let pdu = Pdu {
                    request_id: request_id,
                    error_index: 0,
                    error_status: 0,
                    variable_bindings: vb,
                };
                println!("Should build a Response instead!");
                let resp = Response(pdu);
                let bm = prepare_back(message_id, resp);
                send(&socket, src, bm)
            }
        }
        Pdus::GetNextRequest(r) => {} //let request_id = r.0.request_id},
        Pdus::SetRequest(r) => {}     //et request_id = r.0.request_id},
        _ => {}
    }
    ()
}

fn server_agent(addr_str: &str) -> std::io::Result<()> {
    {
        let socket: UdpSocket = UdpSocket::bind(addr_str)?;
        // Receives a single datagram message on the socket. If `buf` is too small to hold
        // the message, it will be cut off.
        let mut buf = [0; 65100];
        loop {
            let (amt, src) = socket.recv_from(&mut buf)?;

            // Redeclare `buf` as slice of the received data
            let buf = &mut buf[..amt];
            let message = unpack(buf);
            let message_id = message.global_data.message_id;

            match message.scoped_data {
                ScopedPduData::CleartextPdu(scoped_pdu) => {
                    do_scoped_pdu(scoped_pdu, &socket, message_id, src);
                }
                ScopedPduData::EncryptedPdu(_enc_oct) => {
                    println!("Ignoring encrypted")
                }
            }
        }
    } // the socket is closed here
    Ok(())
}

fn main() -> std::io::Result<()> {
    server_agent("127.0.0.1:2161")
}
