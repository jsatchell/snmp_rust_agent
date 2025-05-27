use crate::keeper::oid_keep::{OidKeeper, OidErr, Access, check_otype, check_type};
use rasn::types::ObjectIdentifier;
use rasn_smi::v2::{SimpleSyntax, ObjectSyntax};
use rasn_snmp::v3::{VarBind, VarBindValue};
use log::debug;
use num_traits::cast::ToPrimitive;


pub struct TableMemOid {
    rows: Vec<(Vec<u32>, Vec<ObjectSyntax>)>,
    cols: usize,
    base: Vec<u32>,
    otypes: Vec<char>,
    access: Vec<Access>,
    index_cols: Vec<usize>,
    implied_last: bool,
}

impl TableMemOid {
    pub fn new(
        data: Vec<Vec<ObjectSyntax>>,
        cols: usize,
        base: &ObjectIdentifier,
        otypes: Vec<char>,
        access: Vec<Access>,
        index_cols: Vec<usize>,
        implied_last: bool,
    ) -> Self {
        assert_eq!(cols, otypes.len());
        assert_eq!(cols, access.len());
        for ot in &otypes {
            assert!(check_otype(*ot));
        }
        assert!(index_cols.len() <= cols);
        let mut row_data = Vec::new();
        for row in data {
            let idx = TableMemOid::index_imp(&index_cols, &row, implied_last);
            row_data.push((idx, row));
        }
        row_data.sort_by(|a, b| a.0.cmp(&b.0));
        TableMemOid {
            rows: row_data,
            cols,
            base: base.to_vec(),
            otypes,
            access,
            index_cols,
            implied_last,
        }
    }

    fn index_imp(icols: &[usize], row: &[ObjectSyntax], implied_last: bool) -> Vec<u32> {
        let mut ret: Vec<u32> = Vec::new();
        for (n, index_column_number) in icols.iter().enumerate() {
            let col = &row[*index_column_number - 1];
            match col {
                ObjectSyntax::Simple(SimpleSyntax::Integer(i)) => {
                    let iu32: u32 = i.to_u32().unwrap();
                    ret.push(iu32);
                }
                ObjectSyntax::Simple(SimpleSyntax::String(s)) => {
                    if !implied_last || n < icols.len() - 1 {
                        let sl: u32 = s.len().try_into().unwrap();
                        ret.push(sl);
                    }
                    for i in s {
                        let ir: u8 = *i;
                        let ui32: u32 = ir.into();
                        ret.push(ui32);
                    }
                }
                ObjectSyntax::Simple(SimpleSyntax::ObjectId(o)) => {
                    if !implied_last || n < icols.len() - 1 {
                        let ol: u32 = o.len().try_into().unwrap();
                        ret.push(ol);
                    }
                    for ui32 in o.iter().copied() {
                        ret.push(ui32);
                    }
                }
                _ => {
                    // Could be address, which I haven't met yet
                    panic!("Unsupported type in index construction")
                }
            }
        }
        ret
    }

    fn suffix(&self, oid: ObjectIdentifier) -> Vec<u32> {
        let blen = self.base.len();
        if oid.len() > blen {
            oid.to_vec()[blen..].to_vec()
        } else {
            vec![]
        }
    }

    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    pub fn add_row(&mut self, row: &[ObjectSyntax]) {
        let idx = TableMemOid::index_imp(&self.index_cols, row, self.implied_last);
        // FIXME, replace push / sort by find and insert
        self.rows.push((idx, row.to_owned()));
        self.rows.sort_by(|a, b| a.0.cmp(&b.0));
    }

    /// Generate oid corresponding to column and index
    ///
    /// If the table has OID x.y, the table entry is always x.y.1
    /// Column n definition is x.y.1.n and never has instances
    /// Column n and index m (which could be a whole array) is x.y.1.n.m
    ///
    fn make_oid(&self, col: usize, index: &[u32]) -> ObjectIdentifier {
        let mut tmp = self.base.clone();
        tmp.push(1u32); // Table entry
        let c32: u32 = col.try_into().unwrap();
        tmp.push(c32); // Column
        for i in index {
            tmp.push(*i); // However many pieces of index
        }
        ObjectIdentifier::new(tmp).unwrap().to_owned()
    }
}

impl OidKeeper for TableMemOid {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {
        false
    }

    /// Get value, matching index_fn of row.
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
        let suffix = self.suffix(oid);
        debug!("Suffix is {suffix:?}");
        // Complex indices (not integer and/or multicolumn need longer than 3)
        if suffix.len() < 3 {
            return Err(OidErr::NoSuchInstance);
        }
        if suffix[0] != 1u32 {
            return Err(OidErr::NoSuchName);
        }
        if suffix[1] > 16384 {
            // Some sort of denial of service attack?
            // This would only allow 4 bytes per column in
            // the biggest UDP packet.
            return Err(OidErr::NoSuchName);
        }
        // This is OK on 16 bit and larger machines. Might fail on a microcontroller,
        // but you probably don't want more than 255 columns on such a machine anyway
        let col: usize = suffix[1].try_into().unwrap();
        if col == 0 || col > self.cols {
            return Err(OidErr::NoSuchName);
        }
        let index = &suffix[2..];
        debug!("Col {col} Index is {index:?}");
        // FIXME nice to do something faster than O(N) sequential search
        // Maybe argument for keeping rows sorted by index, then binary_search
        for row in &self.rows {
            let r0 = &row.0;
            debug!("Index {index:?} r0 {r0:?}");
            if index == row.0 {
                return Ok(VarBindValue::Value(row.1[col - 1].clone()));
            }
        }
        Err(OidErr::NoSuchName)
    }

    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
        let suffix = self.suffix(oid);
        let mut col: usize = if suffix.len() < 3 {
            1 + self
                .access
                .iter()
                .position(|p| {
                    *p == Access::ReadOnly
                        || *p == Access::ReadWrite
                        || *p == Access::ReadCreate
                })
                .unwrap()
        } else {
            suffix[1].try_into().unwrap()
        };
        if col == 0 || col > self.cols {
            return Err(OidErr::NoSuchName);
        }
        if self.rows.is_empty() {
            return Err(OidErr::OutOfRange);
        }
        if suffix.len() >= 3 {
            let index = &suffix[2..];
            for (i, row) in self.rows.iter().enumerate() {
                if index == row.0 {
                    if i < self.rows.len() - 1 {
                        let (next_index, next_row) = &self.rows[i + 1];
                        let value = VarBindValue::Value(next_row[col - 1].clone());
                        let name = self.make_oid(col, next_index);
                        return Ok(VarBind { name, value });
                    } else if col < self.cols {
                        col += 1;
                        let value = VarBindValue::Value(self.rows[0].1[col - 1].clone());
                        let name = self.make_oid(col, &self.rows[0].0);
                        return Ok(VarBind { name, value });
                    }
                }
            }
            debug!("Off end of table");
            Err(OidErr::OutOfRange)
        } else {
            let row = &self.rows[0];
            let value = VarBindValue::Value(row.1[col - 1].clone());
            let name = self.make_oid(col, &row.0);
            Ok(VarBind { name, value })
        }
    }

    fn access(&self, oid: ObjectIdentifier) -> Access {
        let suffix = self.suffix(oid);
        if suffix.len() < 2 {
            return Access::NoAccess;
        }
        if suffix[0] != 1u32 {
            return Access::NoAccess;
        }
        if suffix[1] > 16384 {
            return Access::NoAccess;
        }
        let col: usize = suffix[1].try_into().unwrap();
        if col == 0 || col > self.cols {
            return Access::NoAccess;
        }
        self.access[col - 1]
    }

    /// Supports updating existing cells, NOT YET new row creation via RowStatus column
    fn set(
        &mut self,
        oid: ObjectIdentifier,
        value: VarBindValue,
    ) -> Result<VarBindValue, OidErr> {
        let suffix = self.suffix(oid);
        debug!("Suffix is {suffix:?}");
        // Complex indices (not integer and/or multicolumn need longer than 2)
        if suffix.len() < 3 {
            return Err(OidErr::NoSuchInstance);
        }
        if suffix[0] != 1u32 {
            return Err(OidErr::NoSuchName);
        }
        if suffix[1] > 16384 {
            // Some sort of denial of service attack?
            // This would only allow 4 bytes per column
            return Err(OidErr::NoSuchName);
        }
        // This is OK on 16bit and larger machines. Might fail on a microcontroller,
        // but you probably don't want more than 255 columns on such a machine anyway
        let col: usize = suffix[1].try_into().unwrap();
        // col is 1 based, so 0 is wrong
        if col == 0 || col > self.cols {
            return Err(OidErr::NoSuchName);
        }

        match self.access[col - 1] {
            Access::NoAccess | Access::NotificationOnly | Access::ReadOnly => {
                return Err(OidErr::NotWritable);
            }
            _ => {}
        }
        let index = &suffix[2..];
        for row in &mut self.rows {
            if index == row.0 {
                if let VarBindValue::Value(new_value) = value.clone() {
                    if check_type(self.otypes[col - 1], &new_value) {
                        row.1[col - 1] = new_value;
                        return Ok(value);
                    } else {
                        return Err(OidErr::WrongType);
                    }
                }
            }
        }
        Err(OidErr::NoSuchInstance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::{Access, OidErr, OidKeeper as _, TableMemOid};
    use rasn::types::{Integer, ObjectIdentifier};
    use rasn_smi::v2::{ObjectSyntax, SimpleSyntax};
    use rasn_snmp::v3::VarBindValue;

    fn simple_from_int(value: i32) -> ObjectSyntax {
        ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(value)))
    }

    const ARC2: [u32; 2] = [1, 6];

    #[test]
    fn test_simple_from_int() {
        let x = simple_from_int(21);
        assert_eq!(
            x,
            ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(21)))
        );
    }

    fn tab_fixture() -> TableMemOid {
        let oid2: ObjectIdentifier = ObjectIdentifier::new(&ARC2).unwrap();
        let s42 = simple_from_int(42);
        let s41 = simple_from_int(41);
        let s4 = simple_from_int(4);
        let s5 = simple_from_int(5);
        TableMemOid::new(
            vec![vec![s4.clone(), s41.clone()], vec![s5.clone(), s42.clone()]],
            2,
            &oid2,
            vec!['i', 'i'],
            vec![Access::ReadOnly, Access::ReadWrite],
            vec![1usize],
            false,
        )
    }
    #[test]
    fn tab_get_test() {
        let tab = tab_fixture();
        let oid2: ObjectIdentifier = ObjectIdentifier::new(&ARC2).unwrap();
        let res = tab.get(oid2);
        assert_eq!(res, Err(OidErr::NoSuchInstance));
        let o3 = ObjectIdentifier::new(&[1, 6, 1, 1, 5]).unwrap();
        let res = tab.get(o3);
        assert!(res.is_ok());
        let s5 = simple_from_int(5);
        assert_eq!(res.unwrap(), VarBindValue::Value(s5));
        let o4 = ObjectIdentifier::new(&[1, 6, 1, 2, 5]).unwrap();
        let res = tab.get(o4);
        assert!(res.is_ok());
        let s42 = simple_from_int(42);
        assert_eq!(res.unwrap(), VarBindValue::Value(s42));
    }

    #[test]
    fn tab_get_next_test() {
        let oid2: ObjectIdentifier = ObjectIdentifier::new(&ARC2).unwrap();
        let tab = tab_fixture();
        let res = tab.get_next(oid2);
        assert!(res.is_ok());
        let o3 = ObjectIdentifier::new(&[1, 6, 1, 1, 4]).unwrap();
        let res = tab.get_next(o3);
        assert!(res.is_ok());
        let vb = res.unwrap();
        let o4 = ObjectIdentifier::new(&[1, 6, 1, 1, 5]).unwrap();
        assert_eq!(vb.name, o4);
        let o4 = ObjectIdentifier::new(&[1, 6, 1, 1, 5]).unwrap();
        let res = tab.get_next(o4);
        assert!(res.is_ok());
        let vb = res.unwrap();
        let o5 = ObjectIdentifier::new(&[1, 6, 1, 2, 4]).unwrap();
        assert_eq!(vb.name, o5);
        assert_eq!(vb.value, VarBindValue::Value(simple_from_int(41)));
        let res = tab.get_next(o5);
        assert!(res.is_ok());
        let s42 = simple_from_int(42);
        let vb = res.unwrap();
        assert_eq!(vb.value, VarBindValue::Value(s42));
        let ol = ObjectIdentifier::new(&[1, 6, 1, 2, 5]).unwrap();
        let res = tab.get_next(ol);
        assert!(res.is_err());
    }

    #[test]
    fn test_add_row() {
        let mut tab = tab_fixture();
        assert_eq!(tab.row_count(), 2);
        let s6 = simple_from_int(6);
        let s37 = simple_from_int(37);
        let row = vec![s6, s37];
        tab.add_row(&row);
        assert_eq!(tab.row_count(), 3);
    }
}
