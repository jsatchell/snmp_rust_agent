pub mod oid_keep {
    use rasn::types::ObjectIdentifier;
    use rasn_smi::v2::{ApplicationSyntax, ObjectSyntax, SimpleSyntax};
    use rasn_snmp::v3::{VarBind, VarBindValue};

    // Constants for table row management
    /* const ROW_STATUS_ACTIVE: Integer = Integer::Primitive(1);
    const ROW_STATUS_NOT_IN_SERVICE: Integer = Integer::Primitive(2);
    const ROW_STATUS_NOT_READY: Integer = Integer::Primitive(3);
    const ROW_STATUS_CREATE_AND_GO: Integer = Integer::Primitive(4);
    const ROW_STATUS_CREATE_AND_WAIT: Integer = Integer::Primitive(5);
    const ROW_STATUS_DELETE: Integer = Integer::Primitive(6); */

    #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
    pub struct OidErr;

    fn check_type(otype: char, val: &ObjectSyntax) -> bool {
        match val {
            ObjectSyntax::Simple(SimpleSyntax::Integer(_)) => otype == 'i' || otype == 'r',
            ObjectSyntax::Simple(SimpleSyntax::String(_)) => otype == 's',
            ObjectSyntax::Simple(SimpleSyntax::ObjectId(_)) => otype == 'o',
            ObjectSyntax::ApplicationWide(ApplicationSyntax::Address(_)) => otype == 'a',
            ObjectSyntax::ApplicationWide(ApplicationSyntax::Unsigned(_)) => otype == 'u',
            ObjectSyntax::ApplicationWide(ApplicationSyntax::Arbitrary(_)) => otype == '?',
            ObjectSyntax::ApplicationWide(ApplicationSyntax::Counter(_)) => otype == 'c',
            ObjectSyntax::ApplicationWide(ApplicationSyntax::BigCounter(_)) => otype == 'b',
            ObjectSyntax::ApplicationWide(ApplicationSyntax::Ticks(_)) => otype == 't',
        }
    }

    fn check_otype(otype: char) -> bool {
        ['a', 'b', 'c', 'i', 'o', 's', 't', 'u', '?', 'r'].contains(&otype)
    }

    pub trait OidKeeper {
        fn is_scalar(&self) -> bool;
        fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr>;
        fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr>;
        fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr>;
    }

    /// Simplistic scalar stored in memory.
    /// Initialized in constructor.
    pub struct ScalarMemOid {
        value: ObjectSyntax,
        otype: char,
    }

    impl ScalarMemOid {
        /// Initialize with initial value, and char that selects type checking.
        /// Any variant of ObjectSyntax is OK
        ///
        /// There is are self consistency checks that the char is a known one,
        /// and that the initial value is consitent with that type.
        ///
        /// The type mapping is:
        /// * Simple(SimpleSyntax::Integer(_)) => 'i' (also 'r' for RowStatus in tables),
        /// * Simple(SimpleSyntax::String(_)) => 's',
        /// * Simple(SimpleSyntax::ObjectId(_)) => 'o',
        /// * ApplicationWide(ApplicationSyntax::Address(_)) => 'a',
        /// * ApplicationWide(ApplicationSyntax::Unsigned(_)) => 'u',
        /// * ApplicationWide(ApplicationSyntax::Arbitrary(_)) => '?',
        /// * ApplicationWide(ApplicationSyntax::Counter(_)) => 'c',
        /// * ApplicationWide(ApplicationSyntax::BigCounter(_)) => 'b',
        /// * ApplicationWide(ApplicationSyntax::Ticks(_)) => 't',
        pub fn new(value: ObjectSyntax, otype: char) -> Self {
            if !check_otype(otype) {
                panic!("Unrecognised type char {otype}");
            }
            if !check_type(otype, &value) {
                panic!("Initial value is unexpected type {otype} {value:?}");
            }
            ScalarMemOid { value, otype }
        }
    }
    impl OidKeeper for ScalarMemOid {
        fn is_scalar(&self) -> bool {
            true
        }

        fn get(&self, _oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
            Ok(VarBindValue::Value(self.value.clone()))
        }

        // Scalar, so next item always lies outside
        fn get_next(&self, _oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
            Err(OidErr)
        }

        fn set(
            &mut self,
            _oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
            if let VarBindValue::Value(new_value) = value.clone() {
                if check_type(self.otype, &new_value) {
                    self.value = new_value;
                } else {
                    return Err(OidErr);
                }
            }
            Ok(value)
        }
    }

    pub struct TableMemOid {
        rows: Vec<Vec<ObjectSyntax>>,
        cols: usize,
        base: Vec<u32>,
        otypes: Vec<char>,
        index_fn: fn(&[ObjectSyntax]) -> Vec<u32>,
    }

    impl TableMemOid {
        pub fn new(
            data: Vec<Vec<ObjectSyntax>>,
            cols: usize,
            base: &ObjectIdentifier,
            otypes: Vec<char>,
            index_fn: fn(&[ObjectSyntax]) -> Vec<u32>,
        ) -> Self {
            assert_eq!(cols, otypes.len());
            for ot in &otypes {
                assert!(check_otype(*ot));
            }
            TableMemOid {
                rows: data,
                cols,
                base: base.to_vec(),
                otypes,
                index_fn,
            }
        }

        fn suffix(&self, oid: ObjectIdentifier) -> Vec<u32> {
            let blen = self.base.len();
            if oid.len() > blen {
                oid.to_vec()[blen..].to_vec()
            } else {
                vec![]
            }
        }

        fn make_oid(&self, col: usize, index: &[u32]) -> ObjectIdentifier {
            let mut tmp = self.base.clone();
            let c32: u32 = col.try_into().unwrap();
            tmp.push(c32);
            for i in index {
                tmp.push(*i);
            }
            ObjectIdentifier::new(tmp).unwrap().to_owned()
        }
    }

    impl OidKeeper for TableMemOid {
        fn is_scalar(&self) -> bool {
            false
        }

        /// Get value, matching index_fn of row.
        fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
            let suffix = self.suffix(oid);
            println!("Suffix is {suffix:?}");
            // Complex indices (not integer and/or multicolumn need longer than 2)
            if suffix.len() < 2 {
                return Err(OidErr);
            }
            // This is OK on 32bit and larger machines. Might fail on a microcontroller,
            // but you probably don't want more than 255 columns on such a machine anyway
            let col: usize = suffix[0].try_into().unwrap();
            if col == 0 || col > self.cols {
                return Err(OidErr);
            }
            let index = &suffix[1..];
            // FIXME nice to do something faster than O(N) sequential search
            // Maybe argument for keeping rows sorted by index, then binary_search
            for row in &self.rows {
                if index == (self.index_fn)(row) {
                    return Ok(VarBindValue::Value(row[col - 1].clone()));
                }
            }
            Err(OidErr)
        }

        fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
            let suffix = self.suffix(oid);
            let mut col: usize = if suffix.is_empty() {
                1
            } else {
                suffix[0].try_into().unwrap()
            };
            if col == 0 || col > self.cols {
                return Err(OidErr);
            }
            if suffix.len() >= 2 {
                let index = &suffix[1..];
                for (i, row) in self.rows.iter().enumerate() {
                    if index == (self.index_fn)(row) {
                        if i < self.rows.len() - 1 {
                            let value = VarBindValue::Value(row[col - 1].clone());
                            let name = self.make_oid(col, index);
                            return Ok(VarBind { name, value });
                        } else if col < self.cols {
                            col += 1;
                            let value = VarBindValue::Value(self.rows[0][col - 1].clone());
                            let name = self.make_oid(col, &(self.index_fn)(&self.rows[0]));
                            return Ok(VarBind { name, value });
                        }
                    }
                }

                Err(OidErr)
            } else {
                let row = &self.rows[0];
                let value = VarBindValue::Value(row[col].clone());
                let name = self.make_oid(col, &(self.index_fn)(row));
                Ok(VarBind { name, value })
            }
        }

        /// Supports updating existing cells, NOT YET new row creation via RowStatus column
        fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
            let suffix = self.suffix(oid);
            println!("Suffix is {suffix:?}");
            // Complex indices (not integer and/or multicolumn need longer than 2)
            if suffix.len() < 2 {
                return Err(OidErr);
            }
            // This is OK on 32bit and larger machines. Might fail on a microcontroller,
            // but you probably don't want more than 255 columns on such a machine anyway
            let col: usize = suffix[0].try_into().unwrap();
            if col == 0 || col > self.cols {
                return Err(OidErr);
            }
            let index = &suffix[1..];
            for row in &mut self.rows {
                if index == (self.index_fn)(row) {
                    if let VarBindValue::Value(new_value) = value.clone() {
                        if check_type(self.otypes[col - 1], &new_value) {
                            row[col - 1] = new_value;
                            return Ok(value);
                        } else {
                            return Err(OidErr);
                        }
                    }
                }
            }
            Err(OidErr)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oid_keep::{OidErr, OidKeeper as _, TableMemOid};
    use rasn::types::{Integer, ObjectIdentifier};
    use rasn_smi::{
        v1::InvalidVariant,
        v2::{ObjectSyntax, SimpleSyntax},
    };
    use rasn_snmp::v3::VarBindValue;

    fn simple_from_int(value: i32) -> ObjectSyntax {
        ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(value)))
    }

    const ARC2: [u32; 2] = [1, 6];
    fn col1(row: &[ObjectSyntax]) -> Vec<u32> {
        let ind_res: Result<u32, InvalidVariant> = row[0].clone().try_into();
        match ind_res {
            Ok(ind) => {
                vec![ind]
            }
            Err(_) => {
                panic!("Wanted integer in index")
            }
        }
    }
    //use crate::keeper::oid_keep:OidKeeper;
    #[test]
    fn tab_get_test() {
        let oid2: ObjectIdentifier = ObjectIdentifier::new(&ARC2).unwrap();
        let s42 = simple_from_int(42);
        let s5 = simple_from_int(5);
        let tab = TableMemOid::new(vec![vec![s5, s42]], 2, &oid2, vec!['i', 'i'], col1);
        let res = tab.get(oid2);
        assert_eq!(res, Err(OidErr));
        let o3 = ObjectIdentifier::new(&[1, 6, 1, 5]).unwrap();
        let res = tab.get(o3);
        assert!(res.is_ok());
        let s5 = simple_from_int(5);
        assert_eq!(res.unwrap(), VarBindValue::Value(s5));
        let o4 = ObjectIdentifier::new(&[1, 6, 2, 5]).unwrap();
        let res = tab.get(o4);
        assert!(res.is_ok());
        let s42 = simple_from_int(42);
        assert_eq!(res.unwrap(), VarBindValue::Value(s42));
    }

    #[test]
    fn tab_get_next_test() {
        let oid2: ObjectIdentifier = ObjectIdentifier::new(&ARC2).unwrap();
        let s41 = simple_from_int(41);
        let s42 = simple_from_int(42);
        let s5 = simple_from_int(5);
        let s6 = simple_from_int(6);
        let tab = TableMemOid::new(
            vec![vec![s5, s42], vec![s6, s41]],
            2,
            &oid2,
            vec!['i', 'i'],
            col1,
        );
        let res = tab.get_next(oid2);
        assert!(res.is_ok());
        let o3 = ObjectIdentifier::new(&[1, 6, 1, 5]).unwrap();
        let res = tab.get_next(o3);
        assert!(res.is_ok());
        let o4 = ObjectIdentifier::new(&[1, 6, 1, 6]).unwrap();
        let res = tab.get_next(o4);
        assert!(res.is_ok());
        /*let s5 = simple_from_int(5);
        assert_eq!(res.unwrap(), VarBindValue::Value(s5));
        let o4 = ObjectIdentifier::new(&[1, 6, 2, 5]).unwrap();
        let res = tab.get_next(o4);
        assert!(res.is_ok());
        let s42 = simple_from_int(42);
        assert_eq!(res.unwrap(), VarBindValue::Value(s42)); */
    }
}
