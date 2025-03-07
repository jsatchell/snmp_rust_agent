
use crate::keeper::oid_keep::{Access, OidErr, OidKeeper, ScalarMemOid, TableMemOid};
use crate::oidmap::OidMap;
use rasn::types::{Integer, ObjectIdentifier, OctetString};
use rasn_smi::v2::{ObjectSyntax, SimpleSyntax};
use rasn_snmp::v3::{VarBind, VarBindValue};

fn simple_from_int(value: i32) -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(value)))
}

fn simple_from_str() -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::String(OctetString::from_static(b"value")))
}
const ARC_SYS_DESCR: [u32; 8] = [1, 3, 6, 1, 2, 1, 1, 1];
const ARC_SYS_OBJECT_I_D: [u32; 8] = [1, 3, 6, 1, 2, 1, 1, 2];
const ARC_SYS_UP_TIME: [u32; 8] = [1, 3, 6, 1, 2, 1, 1, 3];
const ARC_SYS_CONTACT: [u32; 8] = [1, 3, 6, 1, 2, 1, 1, 4];
const ARC_SYS_NAME: [u32; 8] = [1, 3, 6, 1, 2, 1, 1, 5];
const ARC_SYS_LOCATION: [u32; 8] = [1, 3, 6, 1, 2, 1, 1, 6];
const ARC_SYS_SERVICES: [u32; 8] = [1, 3, 6, 1, 2, 1, 1, 7];
const ARC_SYS_O_R_LAST_CHANGE: [u32; 8] = [1, 3, 6, 1, 2, 1, 1, 8];
const ARC_SYS_O_R_TABLE: [u32; 8] = [1, 3, 6, 1, 2, 1, 1, 9];
const ARC_SNMP_IN_PKTS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 1];
const ARC_SNMP_IN_BAD_VERSIONS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 3];
const ARC_SNMP_IN_BAD_COMMUNITY_NAMES: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 4];
const ARC_SNMP_IN_BAD_COMMUNITY_USES: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 5];
const ARC_SNMP_IN_A_S_N_PARSE_ERRS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 6];
const ARC_SNMP_ENABLE_AUTHEN_TRAPS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 30];
const ARC_SNMP_SILENT_DROPS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 31];
const ARC_SNMP_PROXY_DROPS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 32];
const ARC_SNMP_TRAP_O_I_D: [u32; 10] = [1, 3, 6, 1, 6, 3, 1, 1, 4, 1];
const ARC_SNMP_TRAP_ENTERPRISE: [u32; 10] = [1, 3, 6, 1, 6, 3, 1, 1, 4, 3];
const ARC_SNMP_SET_SERIAL_NO: [u32; 10] = [1, 3, 6, 1, 6, 3, 1, 1, 6, 1];
const ARC_SNMP_OUT_PKTS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 2];
const ARC_SNMP_IN_TOO_BIGS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 8];
const ARC_SNMP_IN_NO_SUCH_NAMES: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 9];
const ARC_SNMP_IN_BAD_VALUES: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 10];
const ARC_SNMP_IN_READ_ONLYS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 11];
const ARC_SNMP_IN_GEN_ERRS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 12];
const ARC_SNMP_IN_TOTAL_REQ_VARS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 13];
const ARC_SNMP_IN_TOTAL_SET_VARS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 14];
const ARC_SNMP_IN_GET_REQUESTS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 15];
const ARC_SNMP_IN_GET_NEXTS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 16];
const ARC_SNMP_IN_SET_REQUESTS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 17];
const ARC_SNMP_IN_GET_RESPONSES: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 18];
const ARC_SNMP_IN_TRAPS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 19];
const ARC_SNMP_OUT_TOO_BIGS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 20];
const ARC_SNMP_OUT_NO_SUCH_NAMES: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 21];
const ARC_SNMP_OUT_BAD_VALUES: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 22];
const ARC_SNMP_OUT_GEN_ERRS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 24];
const ARC_SNMP_OUT_GET_REQUESTS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 25];
const ARC_SNMP_OUT_GET_NEXTS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 26];
const ARC_SNMP_OUT_SET_REQUESTS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 27];
const ARC_SNMP_OUT_GET_RESPONSES: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 28];
const ARC_SNMP_OUT_TRAPS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 29];

   // Now the OBJECT-TYPES. These need actual code

    // A textual description of the entity.  This value should
    // include the full name and version identification of
    // the system's hardware type, software operating-system,
    // and networking software.

struct KeepSysdescr {
    scalar: ScalarMemOid,
  }

impl KeepSysdescr {
    fn new() -> Self {
       KeepSysdescr {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSysdescr {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The vendor's authoritative identification of the
    // network management subsystem contained in the entity.
    // This value is allocated within the SMI enterprises
    // subtree (1.3.6.1.4.1) and provides an easy and
    // unambiguous means for determining `what kind of box' is
    // being managed.  For example, if vendor `Flintstones,
    // Inc.' was assigned the subtree 1.3.6.1.4.1.424242,
    // it could assign the identifier 1.3.6.1.4.1.424242.1.1
    // to its `Fred Router'.

struct KeepSysobjectid {
    scalar: ScalarMemOid,
  }

impl KeepSysobjectid {
    fn new() -> Self {
       KeepSysobjectid {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSysobjectid {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The time (in hundredths of a second) since the
    // network management portion of the system was last
    // re-initialized.

struct KeepSysuptime {
    scalar: ScalarMemOid,
  }

impl KeepSysuptime {
    fn new() -> Self {
       KeepSysuptime {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSysuptime {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The textual identification of the contact person for
    // this managed node, together with information on how
    // to contact this person.  If no contact information is
    // known, the value is the zero-length string.

struct KeepSyscontact {
    scalar: ScalarMemOid,
  }

impl KeepSyscontact {
    fn new() -> Self {
       KeepSyscontact {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadWrite),
       }
    }
}

impl OidKeeper for KeepSyscontact {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // An administratively-assigned name for this managed
    // node.  By convention, this is the node's fully-qualified
    // domain name.  If the name is unknown, the value is
    // the zero-length string.

struct KeepSysname {
    scalar: ScalarMemOid,
  }

impl KeepSysname {
    fn new() -> Self {
       KeepSysname {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadWrite),
       }
    }
}

impl OidKeeper for KeepSysname {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The physical location of this node (e.g., 'telephone
    // closet, 3rd floor').  If the location is unknown, the
    // value is the zero-length string.

struct KeepSyslocation {
    scalar: ScalarMemOid,
  }

impl KeepSyslocation {
    fn new() -> Self {
       KeepSyslocation {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadWrite),
       }
    }
}

impl OidKeeper for KeepSyslocation {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // A value which indicates the set of services that this
    // entity may potentially offer.  The value is a sum.
    // 
    // This sum initially takes the value zero. Then, for
    // each layer, L, in the range 1 through 7, that this node
    // performs transactions for, 2 raised to (L - 1) is added
    // to the sum.  For example, a node which performs only
    // routing functions would have a value of 4 (2^(3-1)).
    // In contrast, a node which is a host offering application
    // services would have a value of 72 (2^(4-1) + 2^(7-1)).
    // Note that in the context of the Internet suite of
    // protocols, values should be calculated accordingly:
    // 
    // layer      functionality
    // 1        physical (e.g., repeaters)
    // 2        datalink/subnetwork (e.g., bridges)
    // 3        internet (e.g., supports the IP)
    // 4        end-to-end  (e.g., supports the TCP)
    // 7        applications (e.g., supports the SMTP)
    // 
    // For systems including OSI protocols, layers 5 and 6
    // may also be counted.

struct KeepSysservices {
    scalar: ScalarMemOid,
  }

impl KeepSysservices {
    fn new() -> Self {
       KeepSysservices {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSysservices {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The value of sysUpTime at the time of the most recent
    // change in state or value of any instance of sysORID.

struct KeepSysorlastchange {
    scalar: ScalarMemOid,
  }

impl KeepSysorlastchange {
    fn new() -> Self {
       KeepSysorlastchange {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSysorlastchange {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // An entry (conceptual row) in the sysORTable.

struct KeepSysortable {
    table: TableMemOid,
  }

impl KeepSysortable {
    fn new() -> Self {
       let base_oid: ObjectIdentifier = 
           ObjectIdentifier::new(&ARC_SYS_O_R_TABLE).unwrap();

       KeepSysortable {
           table: TableMemOid::new(
             vec![vec![simple_from_int(42), simple_from_int(42), simple_from_str(), simple_from_int(42)]],
        4,
        &base_oid,
        vec!['i', 'o', 's', 't'],
        vec![Access::NoAccess, Access::ReadOnly, Access::ReadOnly, Access::ReadOnly],
        vec![1],
        false,
        )
       }
    }
}

impl OidKeeper for KeepSysortable {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {false}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.table.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.table.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.table.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.table.set(oid, value) }
}
    // The total number of messages delivered to the SNMP
    // entity from the transport service.

struct KeepSnmpinpkts {
    scalar: ScalarMemOid,
  }

impl KeepSnmpinpkts {
    fn new() -> Self {
       KeepSnmpinpkts {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpinpkts {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The total number of SNMP messages which were delivered
    // to the SNMP entity and were for an unsupported SNMP
    // version.

struct KeepSnmpinbadversions {
    scalar: ScalarMemOid,
  }

impl KeepSnmpinbadversions {
    fn new() -> Self {
       KeepSnmpinbadversions {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpinbadversions {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The total number of community-based SNMP messages (for
    // example,  SNMPv1) delivered to the SNMP entity which
    // used an SNMP community name not known to said entity.
    // Also, implementations which authenticate community-based
    // SNMP messages using check(s) in addition to matching
    // the community name (for example, by also checking
    // whether the message originated from a transport address
    // allowed to use a specified community name) MAY include
    // in this value the number of messages which failed the
    // additional check(s).  It is strongly RECOMMENDED that
    // 
    // the documentation for any security model which is used
    // to authenticate community-based SNMP messages specify
    // the precise conditions that contribute to this value.

struct KeepSnmpinbadcommunitynames {
    scalar: ScalarMemOid,
  }

impl KeepSnmpinbadcommunitynames {
    fn new() -> Self {
       KeepSnmpinbadcommunitynames {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpinbadcommunitynames {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The total number of community-based SNMP messages (for
    // example, SNMPv1) delivered to the SNMP entity which
    // represented an SNMP operation that was not allowed for
    // the SNMP community named in the message.  The precise
    // conditions under which this counter is incremented
    // (if at all) depend on how the SNMP entity implements
    // its access control mechanism and how its applications
    // interact with that access control mechanism.  It is
    // strongly RECOMMENDED that the documentation for any
    // access control mechanism which is used to control access
    // to and visibility of MIB instrumentation specify the
    // precise conditions that contribute to this value.

struct KeepSnmpinbadcommunityuses {
    scalar: ScalarMemOid,
  }

impl KeepSnmpinbadcommunityuses {
    fn new() -> Self {
       KeepSnmpinbadcommunityuses {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpinbadcommunityuses {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The total number of ASN.1 or BER errors encountered by
    // the SNMP entity when decoding received SNMP messages.

struct KeepSnmpinasnparseerrs {
    scalar: ScalarMemOid,
  }

impl KeepSnmpinasnparseerrs {
    fn new() -> Self {
       KeepSnmpinasnparseerrs {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpinasnparseerrs {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // Indicates whether the SNMP entity is permitted to
    // generate authenticationFailure traps.  The value of this
    // object overrides any configuration information; as such,
    // it provides a means whereby all authenticationFailure
    // traps may be disabled.
    // 
    // Note that it is strongly recommended that this object
    // be stored in non-volatile memory so that it remains
    // constant across re-initializations of the network
    // management system.

struct KeepSnmpenableauthentraps {
    scalar: ScalarMemOid,
  }

impl KeepSnmpenableauthentraps {
    fn new() -> Self {
       KeepSnmpenableauthentraps {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadWrite),
       }
    }
}

impl OidKeeper for KeepSnmpenableauthentraps {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The total number of Confirmed Class PDUs (such as
    // GetRequest-PDUs, GetNextRequest-PDUs,
    // GetBulkRequest-PDUs, SetRequest-PDUs, and
    // InformRequest-PDUs) delivered to the SNMP entity which
    // were silently dropped because the size of a reply
    // containing an alternate Response Class PDU (such as a
    // Response-PDU) with an empty variable-bindings field
    // was greater than either a local constraint or the
    // maximum message size associated with the originator of
    // the request.

struct KeepSnmpsilentdrops {
    scalar: ScalarMemOid,
  }

impl KeepSnmpsilentdrops {
    fn new() -> Self {
       KeepSnmpsilentdrops {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpsilentdrops {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The total number of Confirmed Class PDUs
    // (such as GetRequest-PDUs, GetNextRequest-PDUs,
    // GetBulkRequest-PDUs, SetRequest-PDUs, and
    // InformRequest-PDUs) delivered to the SNMP entity which
    // were silently dropped because the transmission of
    // the (possibly translated) message to a proxy target
    // failed in a manner (other than a time-out) such that
    // no Response Class PDU (such as a Response-PDU) could
    // be returned.

struct KeepSnmpproxydrops {
    scalar: ScalarMemOid,
  }

impl KeepSnmpproxydrops {
    fn new() -> Self {
       KeepSnmpproxydrops {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpproxydrops {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The authoritative identification of the notification
    // currently being sent.  This variable occurs as
    // the second varbind in every SNMPv2-Trap-PDU and
    // InformRequest-PDU.

struct KeepSnmptrapoid {
    scalar: ScalarMemOid,
  }

impl KeepSnmptrapoid {
    fn new() -> Self {
       KeepSnmptrapoid {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::NotificationOnly),
       }
    }
}

impl OidKeeper for KeepSnmptrapoid {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The authoritative identification of the enterprise
    // associated with the trap currently being sent.  When an
    // SNMP proxy agent is mapping an RFC1157 Trap-PDU
    // into a SNMPv2-Trap-PDU, this variable occurs as the
    // last varbind.

struct KeepSnmptrapenterprise {
    scalar: ScalarMemOid,
  }

impl KeepSnmptrapenterprise {
    fn new() -> Self {
       KeepSnmptrapenterprise {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::NotificationOnly),
       }
    }
}

impl OidKeeper for KeepSnmptrapenterprise {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // An advisory lock used to allow several cooperating
    // command generator applications to coordinate their
    // use of the SNMP set operation.
    // 
    // This object is used for coarse-grain coordination.
    // To achieve fine-grain coordination, one or more similar
    // objects might be defined within each MIB group, as
    // appropriate.

struct KeepSnmpsetserialno {
    scalar: ScalarMemOid,
  }

impl KeepSnmpsetserialno {
    fn new() -> Self {
       KeepSnmpsetserialno {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadWrite),
       }
    }
}

impl OidKeeper for KeepSnmpsetserialno {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The total number of SNMP Messages which were
    // passed from the SNMP protocol entity to the
    // transport service.

struct KeepSnmpoutpkts {
    scalar: ScalarMemOid,
  }

impl KeepSnmpoutpkts {
    fn new() -> Self {
       KeepSnmpoutpkts {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpoutpkts {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The total number of SNMP PDUs which were
    // delivered to the SNMP protocol entity and for
    // which the value of the error-status field was
    // `tooBig'.

struct KeepSnmpintoobigs {
    scalar: ScalarMemOid,
  }

impl KeepSnmpintoobigs {
    fn new() -> Self {
       KeepSnmpintoobigs {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpintoobigs {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The total number of SNMP PDUs which were
    // delivered to the SNMP protocol entity and for
    // which the value of the error-status field was
    // `noSuchName'.

struct KeepSnmpinnosuchnames {
    scalar: ScalarMemOid,
  }

impl KeepSnmpinnosuchnames {
    fn new() -> Self {
       KeepSnmpinnosuchnames {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpinnosuchnames {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The total number of SNMP PDUs which were
    // delivered to the SNMP protocol entity and for
    // which the value of the error-status field was
    // `badValue'.

struct KeepSnmpinbadvalues {
    scalar: ScalarMemOid,
  }

impl KeepSnmpinbadvalues {
    fn new() -> Self {
       KeepSnmpinbadvalues {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpinbadvalues {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The total number valid SNMP PDUs which were delivered
    // to the SNMP protocol entity and for which the value
    // of the error-status field was `readOnly'.  It should
    // be noted that it is a protocol error to generate an
    // SNMP PDU which contains the value `readOnly' in the
    // error-status field, as such this object is provided
    // as a means of detecting incorrect implementations of
    // the SNMP.

struct KeepSnmpinreadonlys {
    scalar: ScalarMemOid,
  }

impl KeepSnmpinreadonlys {
    fn new() -> Self {
       KeepSnmpinreadonlys {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpinreadonlys {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The total number of SNMP PDUs which were delivered
    // to the SNMP protocol entity and for which the value
    // of the error-status field was `genErr'.

struct KeepSnmpingenerrs {
    scalar: ScalarMemOid,
  }

impl KeepSnmpingenerrs {
    fn new() -> Self {
       KeepSnmpingenerrs {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpingenerrs {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The total number of MIB objects which have been
    // retrieved successfully by the SNMP protocol entity
    // as the result of receiving valid SNMP Get-Request
    // and Get-Next PDUs.

struct KeepSnmpintotalreqvars {
    scalar: ScalarMemOid,
  }

impl KeepSnmpintotalreqvars {
    fn new() -> Self {
       KeepSnmpintotalreqvars {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpintotalreqvars {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The total number of MIB objects which have been
    // altered successfully by the SNMP protocol entity as
    // the result of receiving valid SNMP Set-Request PDUs.

struct KeepSnmpintotalsetvars {
    scalar: ScalarMemOid,
  }

impl KeepSnmpintotalsetvars {
    fn new() -> Self {
       KeepSnmpintotalsetvars {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpintotalsetvars {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The total number of SNMP Get-Request PDUs which
    // have been accepted and processed by the SNMP
    // protocol entity.

struct KeepSnmpingetrequests {
    scalar: ScalarMemOid,
  }

impl KeepSnmpingetrequests {
    fn new() -> Self {
       KeepSnmpingetrequests {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpingetrequests {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The total number of SNMP Get-Next PDUs which have been
    // accepted and processed by the SNMP protocol entity.

struct KeepSnmpingetnexts {
    scalar: ScalarMemOid,
  }

impl KeepSnmpingetnexts {
    fn new() -> Self {
       KeepSnmpingetnexts {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpingetnexts {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The total number of SNMP Set-Request PDUs which
    // have been accepted and processed by the SNMP protocol
    // entity.

struct KeepSnmpinsetrequests {
    scalar: ScalarMemOid,
  }

impl KeepSnmpinsetrequests {
    fn new() -> Self {
       KeepSnmpinsetrequests {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpinsetrequests {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The total number of SNMP Get-Response PDUs which
    // have been accepted and processed by the SNMP protocol
    // entity.

struct KeepSnmpingetresponses {
    scalar: ScalarMemOid,
  }

impl KeepSnmpingetresponses {
    fn new() -> Self {
       KeepSnmpingetresponses {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpingetresponses {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The total number of SNMP Trap PDUs which have been
    // accepted and processed by the SNMP protocol entity.

struct KeepSnmpintraps {
    scalar: ScalarMemOid,
  }

impl KeepSnmpintraps {
    fn new() -> Self {
       KeepSnmpintraps {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpintraps {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The total number of SNMP PDUs which were generated
    // by the SNMP protocol entity and for which the value
    // of the error-status field was `tooBig.'

struct KeepSnmpouttoobigs {
    scalar: ScalarMemOid,
  }

impl KeepSnmpouttoobigs {
    fn new() -> Self {
       KeepSnmpouttoobigs {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpouttoobigs {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The total number of SNMP PDUs which were generated
    // by the SNMP protocol entity and for which the value
    // of the error-status was `noSuchName'.

struct KeepSnmpoutnosuchnames {
    scalar: ScalarMemOid,
  }

impl KeepSnmpoutnosuchnames {
    fn new() -> Self {
       KeepSnmpoutnosuchnames {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpoutnosuchnames {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The total number of SNMP PDUs which were generated
    // by the SNMP protocol entity and for which the value
    // of the error-status field was `badValue'.

struct KeepSnmpoutbadvalues {
    scalar: ScalarMemOid,
  }

impl KeepSnmpoutbadvalues {
    fn new() -> Self {
       KeepSnmpoutbadvalues {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpoutbadvalues {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The total number of SNMP PDUs which were generated
    // by the SNMP protocol entity and for which the value
    // of the error-status field was `genErr'.

struct KeepSnmpoutgenerrs {
    scalar: ScalarMemOid,
  }

impl KeepSnmpoutgenerrs {
    fn new() -> Self {
       KeepSnmpoutgenerrs {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpoutgenerrs {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The total number of SNMP Get-Request PDUs which
    // have been generated by the SNMP protocol entity.

struct KeepSnmpoutgetrequests {
    scalar: ScalarMemOid,
  }

impl KeepSnmpoutgetrequests {
    fn new() -> Self {
       KeepSnmpoutgetrequests {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpoutgetrequests {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The total number of SNMP Get-Next PDUs which have
    // been generated by the SNMP protocol entity.

struct KeepSnmpoutgetnexts {
    scalar: ScalarMemOid,
  }

impl KeepSnmpoutgetnexts {
    fn new() -> Self {
       KeepSnmpoutgetnexts {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpoutgetnexts {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The total number of SNMP Set-Request PDUs which
    // have been generated by the SNMP protocol entity.

struct KeepSnmpoutsetrequests {
    scalar: ScalarMemOid,
  }

impl KeepSnmpoutsetrequests {
    fn new() -> Self {
       KeepSnmpoutsetrequests {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpoutsetrequests {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The total number of SNMP Get-Response PDUs which
    // have been generated by the SNMP protocol entity.

struct KeepSnmpoutgetresponses {
    scalar: ScalarMemOid,
  }

impl KeepSnmpoutgetresponses {
    fn new() -> Self {
       KeepSnmpoutgetresponses {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpoutgetresponses {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}
    // The total number of SNMP Trap PDUs which have
    // been generated by the SNMP protocol entity.

struct KeepSnmpouttraps {
    scalar: ScalarMemOid,
  }

impl KeepSnmpouttraps {
    fn new() -> Self {
       KeepSnmpouttraps {
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepSnmpouttraps {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}


pub fn load_stub(oid_map: &mut OidMap) {
    let s42 = simple_from_int(42);
    let sval = simple_from_str();
    let oid_sys_descr: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SYS_DESCR).unwrap();
    let k_sys_descr: Box<dyn OidKeeper> = 
       Box::new(KeepSysdescr::new());
    oid_map.push(oid_sys_descr, k_sys_descr);
    let oid_sys_object_i_d: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SYS_OBJECT_I_D).unwrap();
    let k_sys_object_i_d: Box<dyn OidKeeper> = 
       Box::new(KeepSysobjectid::new());
    oid_map.push(oid_sys_object_i_d, k_sys_object_i_d);
    let oid_sys_up_time: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SYS_UP_TIME).unwrap();
    let k_sys_up_time: Box<dyn OidKeeper> = 
       Box::new(KeepSysuptime::new());
    oid_map.push(oid_sys_up_time, k_sys_up_time);
    let oid_sys_contact: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SYS_CONTACT).unwrap();
    let k_sys_contact: Box<dyn OidKeeper> = 
       Box::new(KeepSyscontact::new());
    oid_map.push(oid_sys_contact, k_sys_contact);
    let oid_sys_name: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SYS_NAME).unwrap();
    let k_sys_name: Box<dyn OidKeeper> = 
       Box::new(KeepSysname::new());
    oid_map.push(oid_sys_name, k_sys_name);
    let oid_sys_location: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SYS_LOCATION).unwrap();
    let k_sys_location: Box<dyn OidKeeper> = 
       Box::new(KeepSyslocation::new());
    oid_map.push(oid_sys_location, k_sys_location);
    let oid_sys_services: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SYS_SERVICES).unwrap();
    let k_sys_services: Box<dyn OidKeeper> = 
       Box::new(KeepSysservices::new());
    oid_map.push(oid_sys_services, k_sys_services);
    let oid_sys_o_r_last_change: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SYS_O_R_LAST_CHANGE).unwrap();
    let k_sys_o_r_last_change: Box<dyn OidKeeper> = 
       Box::new(KeepSysorlastchange::new());
    oid_map.push(oid_sys_o_r_last_change, k_sys_o_r_last_change);
    let oid_sys_o_r_table: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SYS_O_R_TABLE).unwrap();
    let k_sys_o_r_table: Box<dyn OidKeeper> = 
       Box::new(KeepSysortable::new());
    oid_map.push(oid_sys_o_r_table, k_sys_o_r_table);
    let oid_snmp_in_pkts: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_PKTS).unwrap();
    let k_snmp_in_pkts: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpinpkts::new());
    oid_map.push(oid_snmp_in_pkts, k_snmp_in_pkts);
    let oid_snmp_in_bad_versions: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_BAD_VERSIONS).unwrap();
    let k_snmp_in_bad_versions: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpinbadversions::new());
    oid_map.push(oid_snmp_in_bad_versions, k_snmp_in_bad_versions);
    let oid_snmp_in_bad_community_names: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_BAD_COMMUNITY_NAMES).unwrap();
    let k_snmp_in_bad_community_names: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpinbadcommunitynames::new());
    oid_map.push(oid_snmp_in_bad_community_names, k_snmp_in_bad_community_names);
    let oid_snmp_in_bad_community_uses: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_BAD_COMMUNITY_USES).unwrap();
    let k_snmp_in_bad_community_uses: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpinbadcommunityuses::new());
    oid_map.push(oid_snmp_in_bad_community_uses, k_snmp_in_bad_community_uses);
    let oid_snmp_in_a_s_n_parse_errs: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_A_S_N_PARSE_ERRS).unwrap();
    let k_snmp_in_a_s_n_parse_errs: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpinasnparseerrs::new());
    oid_map.push(oid_snmp_in_a_s_n_parse_errs, k_snmp_in_a_s_n_parse_errs);
    let oid_snmp_enable_authen_traps: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_ENABLE_AUTHEN_TRAPS).unwrap();
    let k_snmp_enable_authen_traps: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpenableauthentraps::new());
    oid_map.push(oid_snmp_enable_authen_traps, k_snmp_enable_authen_traps);
    let oid_snmp_silent_drops: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_SILENT_DROPS).unwrap();
    let k_snmp_silent_drops: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpsilentdrops::new());
    oid_map.push(oid_snmp_silent_drops, k_snmp_silent_drops);
    let oid_snmp_proxy_drops: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_PROXY_DROPS).unwrap();
    let k_snmp_proxy_drops: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpproxydrops::new());
    oid_map.push(oid_snmp_proxy_drops, k_snmp_proxy_drops);
    let oid_snmp_trap_o_i_d: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_TRAP_O_I_D).unwrap();
    let k_snmp_trap_o_i_d: Box<dyn OidKeeper> = 
       Box::new(KeepSnmptrapoid::new());
    oid_map.push(oid_snmp_trap_o_i_d, k_snmp_trap_o_i_d);
    let oid_snmp_trap_enterprise: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_TRAP_ENTERPRISE).unwrap();
    let k_snmp_trap_enterprise: Box<dyn OidKeeper> = 
       Box::new(KeepSnmptrapenterprise::new());
    oid_map.push(oid_snmp_trap_enterprise, k_snmp_trap_enterprise);
    let oid_snmp_set_serial_no: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_SET_SERIAL_NO).unwrap();
    let k_snmp_set_serial_no: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpsetserialno::new());
    oid_map.push(oid_snmp_set_serial_no, k_snmp_set_serial_no);
    let oid_snmp_out_pkts: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_OUT_PKTS).unwrap();
    let k_snmp_out_pkts: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpoutpkts::new());
    oid_map.push(oid_snmp_out_pkts, k_snmp_out_pkts);
    let oid_snmp_in_too_bigs: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_TOO_BIGS).unwrap();
    let k_snmp_in_too_bigs: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpintoobigs::new());
    oid_map.push(oid_snmp_in_too_bigs, k_snmp_in_too_bigs);
    let oid_snmp_in_no_such_names: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_NO_SUCH_NAMES).unwrap();
    let k_snmp_in_no_such_names: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpinnosuchnames::new());
    oid_map.push(oid_snmp_in_no_such_names, k_snmp_in_no_such_names);
    let oid_snmp_in_bad_values: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_BAD_VALUES).unwrap();
    let k_snmp_in_bad_values: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpinbadvalues::new());
    oid_map.push(oid_snmp_in_bad_values, k_snmp_in_bad_values);
    let oid_snmp_in_read_onlys: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_READ_ONLYS).unwrap();
    let k_snmp_in_read_onlys: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpinreadonlys::new());
    oid_map.push(oid_snmp_in_read_onlys, k_snmp_in_read_onlys);
    let oid_snmp_in_gen_errs: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_GEN_ERRS).unwrap();
    let k_snmp_in_gen_errs: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpingenerrs::new());
    oid_map.push(oid_snmp_in_gen_errs, k_snmp_in_gen_errs);
    let oid_snmp_in_total_req_vars: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_TOTAL_REQ_VARS).unwrap();
    let k_snmp_in_total_req_vars: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpintotalreqvars::new());
    oid_map.push(oid_snmp_in_total_req_vars, k_snmp_in_total_req_vars);
    let oid_snmp_in_total_set_vars: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_TOTAL_SET_VARS).unwrap();
    let k_snmp_in_total_set_vars: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpintotalsetvars::new());
    oid_map.push(oid_snmp_in_total_set_vars, k_snmp_in_total_set_vars);
    let oid_snmp_in_get_requests: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_GET_REQUESTS).unwrap();
    let k_snmp_in_get_requests: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpingetrequests::new());
    oid_map.push(oid_snmp_in_get_requests, k_snmp_in_get_requests);
    let oid_snmp_in_get_nexts: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_GET_NEXTS).unwrap();
    let k_snmp_in_get_nexts: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpingetnexts::new());
    oid_map.push(oid_snmp_in_get_nexts, k_snmp_in_get_nexts);
    let oid_snmp_in_set_requests: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_SET_REQUESTS).unwrap();
    let k_snmp_in_set_requests: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpinsetrequests::new());
    oid_map.push(oid_snmp_in_set_requests, k_snmp_in_set_requests);
    let oid_snmp_in_get_responses: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_GET_RESPONSES).unwrap();
    let k_snmp_in_get_responses: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpingetresponses::new());
    oid_map.push(oid_snmp_in_get_responses, k_snmp_in_get_responses);
    let oid_snmp_in_traps: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_TRAPS).unwrap();
    let k_snmp_in_traps: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpintraps::new());
    oid_map.push(oid_snmp_in_traps, k_snmp_in_traps);
    let oid_snmp_out_too_bigs: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_OUT_TOO_BIGS).unwrap();
    let k_snmp_out_too_bigs: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpouttoobigs::new());
    oid_map.push(oid_snmp_out_too_bigs, k_snmp_out_too_bigs);
    let oid_snmp_out_no_such_names: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_OUT_NO_SUCH_NAMES).unwrap();
    let k_snmp_out_no_such_names: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpoutnosuchnames::new());
    oid_map.push(oid_snmp_out_no_such_names, k_snmp_out_no_such_names);
    let oid_snmp_out_bad_values: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_OUT_BAD_VALUES).unwrap();
    let k_snmp_out_bad_values: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpoutbadvalues::new());
    oid_map.push(oid_snmp_out_bad_values, k_snmp_out_bad_values);
    let oid_snmp_out_gen_errs: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_OUT_GEN_ERRS).unwrap();
    let k_snmp_out_gen_errs: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpoutgenerrs::new());
    oid_map.push(oid_snmp_out_gen_errs, k_snmp_out_gen_errs);
    let oid_snmp_out_get_requests: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_OUT_GET_REQUESTS).unwrap();
    let k_snmp_out_get_requests: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpoutgetrequests::new());
    oid_map.push(oid_snmp_out_get_requests, k_snmp_out_get_requests);
    let oid_snmp_out_get_nexts: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_OUT_GET_NEXTS).unwrap();
    let k_snmp_out_get_nexts: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpoutgetnexts::new());
    oid_map.push(oid_snmp_out_get_nexts, k_snmp_out_get_nexts);
    let oid_snmp_out_set_requests: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_OUT_SET_REQUESTS).unwrap();
    let k_snmp_out_set_requests: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpoutsetrequests::new());
    oid_map.push(oid_snmp_out_set_requests, k_snmp_out_set_requests);
    let oid_snmp_out_get_responses: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_OUT_GET_RESPONSES).unwrap();
    let k_snmp_out_get_responses: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpoutgetresponses::new());
    oid_map.push(oid_snmp_out_get_responses, k_snmp_out_get_responses);
    let oid_snmp_out_traps: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_OUT_TRAPS).unwrap();
    let k_snmp_out_traps: Box<dyn OidKeeper> = 
       Box::new(KeepSnmpouttraps::new());
    oid_map.push(oid_snmp_out_traps, k_snmp_out_traps);
}