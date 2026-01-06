use rasn::types::{Integer, ObjectIdentifier, OctetString};
use rasn_smi::v2::{ApplicationSyntax, SimpleSyntax, TimeTicks};
use rasn_snmp::v2::{ObjectSyntax, Pdu, Trap, VarBind, VarBindList, VarBindValue};
//use rasn_snmp::v3::{
//    HeaderData, Message, Pdus, ScopedPdu, ScopedPduData, Trap, USMSecurityParameters, VarBind,
//};
use rasn_snmp::v2c::Message;
use std::net::UdpSocket;
//use std::str::FromStr;
use log::{info, warn};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread::{self};
use std::time::Instant;

const ARC_TRAP_OID: [u32; 11] = [1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0];
const ARC_SYS_UP_TIME: [u32; 9] = [1, 3, 6, 1, 2, 1, 1, 3, 0];

#[derive(Debug)]
/// Data structure to be passed down the channel to trigger a notification.
///
pub struct Notification {
    /// OID that identifies the notification type
    pub name: ObjectIdentifier,
    /// Possibly empty list of Varbinds that conveys details associated with the notification.
    pub vb: VarBindList,
}

/// Private data structure for notification thread.
pub struct Notifier {
    socket: UdpSocket,
    community: Vec<u8>,
    _engine_id: OctetString,
    start_time: Instant,
    request_id: i32,
    _message_id: i32,
    target_addr: String,
    receiver: Receiver<Notification>,
}

impl Notifier {
    /// Constructor for notification struct. Arguments set some private fields.
    fn new(
        target: &str,
        engine_id: OctetString,
        start_time: Instant,
        community: Vec<u8>,
        rx: Receiver<Notification>,
    ) -> Self {
        let socket: UdpSocket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");

        Notifier {
            socket,
            _engine_id: engine_id,
            start_time,
            community,
            request_id: rand::random::<i32>(),
            _message_id: rand::random::<i32>(),
            target_addr: target.to_string(),
            receiver: rx,
        }
    }

    /// Start the notification thread.
    ///
    /// target is the address and port of the notification sink. Convenetionally, this will be on port 162.
    /// community is the community string of the trap receiver; "public" is a common value.
    /// engine_id is not used in v2, but would be in v3.
    /// start_time is when the agent started, used for generating the timestamps on notifications.
    pub fn start(
        target: &str,
        community: &str,
        engine_id: OctetString,
        start_time: Instant,
    ) -> Sender<Notification> {
        let (tx, rx): (Sender<Notification>, Receiver<Notification>) = channel();
        let zero_dot_zero = ObjectIdentifier::new(&[0, 0]).unwrap(); //Checked, valid arc
        let mut notif = Notifier::new(
            target,
            engine_id,
            start_time,
            community.as_bytes().to_vec(),
            rx,
        );

        let _child = thread::spawn(move || {
            // The thread takes ownership over `rx`
            // Each thread queues a message in the channel
            let socket = notif.socket.try_clone().unwrap(); // Checked, startup failure only
            let target_addr = notif.target_addr.clone();
            loop {
                let val = notif.receiver.recv();
                if let Ok(num) = val {
                    info!("Notifier got {num:?}");
                    if num.name == zero_dot_zero {
                        break;
                    }
                    // Ignore send or encode errors
                    if let Ok(msg) = rasn::ber::encode(&notif.msg_v2_trap(num)) {
                        let _ = socket.send_to(&msg, &target_addr);
                    } else {
                        warn!(
                            "Encode error in notification sending, discarding message without send"
                        );
                    }
                } // Just ignore receive errors
            }

            // Sending is a non-blocking operation, the thread will continue
            // immediately after sending its message
            warn!("thread finished");
        });
        tx
    }

    /// Send an SNMP V2 Trap.
    ///
    /// This is fire and forget - there is no check that the packet has arrived at the far end.
    ///
    pub fn msg_v2_trap(&mut self, num: Notification) -> Message<Trap> {
        let up = self.start_time.elapsed().as_millis() / 10;
        let run_time = up.try_into().unwrap_or(u32::MAX); // Checked, alternative value

        self.request_id += 1;
        let mut vb: VarBindList = vec![
            VarBind {
                name: ObjectIdentifier::new(&ARC_SYS_UP_TIME).unwrap(), // Checked, valid arc
                value: VarBindValue::Value(ObjectSyntax::ApplicationWide(
                    ApplicationSyntax::Ticks(TimeTicks { 0: run_time }),
                )),
            },
            VarBind {
                name: ObjectIdentifier::new(&ARC_TRAP_OID).unwrap(), // Checked, valid arc
                value: VarBindValue::Value(ObjectSyntax::Simple(SimpleSyntax::ObjectId(num.name))),
            },
        ];
        if !num.vb.is_empty() {
            vb.extend(num.vb);
        }
        let pdu = Pdu {
            request_id: self.request_id,
            error_index: 0,
            error_status: 0,
            variable_bindings: vb,
        };

        let trap: Trap = Trap(pdu);
        Message::<Trap> {
            version: Integer::from(1),
            community: OctetString::from_slice(&self.community),
            data: trap,
        }
    }
}
