use rasn::types::{Integer, OctetString};
use rasn_snmp::v2::{Pdu, VarBindList};
use rasn_snmp::v3::{
    HeaderData, Message, Pdus, ScopedPdu, ScopedPduData, Trap, USMSecurityParameters, VarBind,
};
use std::net::{SocketAddr, UdpSocket};
//use std::str::FromStr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::Instant;

const ZB: OctetString = OctetString::from_static(b"");

pub struct Notifier {
    socket: UdpSocket,
    engine_id: OctetString,
    start_time: Instant,
    request_id: i32,
    message_id: i32,
    target_addr: String,
    child: JoinHandle<()>,
    pub sender: Sender<i32>,
}

impl Notifier {
    pub fn new(target: &str, engine_id: OctetString, start_time: Instant) -> Self {
        let (tx, rx): (Sender<i32>, Receiver<i32>) = channel();
        let socket: UdpSocket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");

        let child = thread::spawn(move || {
            // The thread takes ownership over `rx`
            // Each thread queues a message in the channel
            loop {
                let val = rx.recv();
                if let Ok(num) = val {
                    println!("Notifier got {num}");
                    // FIXME send an actual message
                    if num == 137 {
                        break;
                    }
                } // Just ignore receive errors
            }

            // Sending is a non-blocking operation, the thread will continue
            // immediately after sending its message
            println!("thread finished");
        });

        Notifier {
            socket,
            engine_id,
            start_time,
            request_id: rand::random::<i32>(),
            message_id: rand::random::<i32>(),
            target_addr: target.to_string(),
            child,
            sender: tx,
        }
    }

    pub fn msg_trap(self, vb: Vec<VarBind>) -> Message {
        /*let vb: Vec<VarBind> = vec![VarBind {
            name: ObjectIdentifier::new_unchecked(vec![1, 3, 6, 1, 6, 3, 15, 1, 1, 4].into()),
            value: VarBindValue::Value(ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(
                self.unknown_engine_ids,
            )))),
        }];*/

        let pdu = Pdu {
            request_id: self.request_id,
            error_index: 0,
            error_status: 0,
            variable_bindings: vb,
        };
        let trap: Trap = Trap(pdu);
        let head = HeaderData {
            flags: OctetString::from_static(b"\x00"),
            message_id: Integer::from(self.message_id),
            max_size: Integer::from(65000),
            security_model: Integer::from(3),
        };
        let scpd: ScopedPdu = ScopedPdu {
            engine_id: self.engine_id.clone(),
            name: OctetString::from_static(b""),
            data: Pdus::Trap(trap),
        };
        let spd: ScopedPduData = ScopedPduData::CleartextPdu(scpd);
        let run_time: isize = self
            .start_time
            .elapsed()
            .as_secs()
            .try_into()
            .unwrap_or(isize::MAX);
        let usm: USMSecurityParameters = USMSecurityParameters {
            authoritative_engine_boots: Integer::from(0), //self.boots),
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
}
