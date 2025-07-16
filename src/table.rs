use crate::keeper::{check_type, Access, OType, OidErr, OidKeeper};
use log::{debug, warn};
use num_traits::cast::ToPrimitive;
use rasn::types::{Integer, ObjectIdentifier, OctetString};
use rasn_smi::v2::{ObjectSyntax, SimpleSyntax};
use rasn_snmp::v3::{VarBind, VarBindValue};

pub const ROW_STATUS_ACTIVE: u32 = 1u32;
pub const ROW_STATUS_NOT_IN_SERVICE: u32 = 2u32;
pub const ROW_STATUS_NOT_READY: u32 = 3u32;
pub const ROW_STATUS_CREATE_AND_GO: u32 = 4u32;
pub const ROW_STATUS_CREATE_AND_WAIT: u32 = 5u32;
pub const ROW_STATUS_DESTROY: u32 = 6u32;

pub struct TableMemOid {
    rows: Vec<(Vec<u32>, Vec<ObjectSyntax>)>,
    default_row: Vec<ObjectSyntax>,
    cols: usize,
    base: Vec<u32>,
    otypes: Vec<OType>,
    access: Vec<Access>,
    index_cols: Vec<usize>,
    implied_last: bool,
}

impl TableMemOid {
    pub fn new(
        data: Vec<Vec<ObjectSyntax>>,
        default_row: Vec<ObjectSyntax>,
        cols: usize,
        base: &ObjectIdentifier,
        otypes: Vec<OType>,
        access: Vec<Access>,
        index_cols: Vec<usize>,
        implied_last: bool,
    ) -> Self {
        assert_eq!(cols, otypes.len());
        assert_eq!(cols, access.len());
        assert_eq!(cols, default_row.len());
        assert!(index_cols.len() <= cols);
        let mut row_data = Vec::new();
        for row in data {
            let idx = TableMemOid::index_imp(&index_cols, &row, implied_last);
            row_data.push((idx, row));
        }
        row_data.sort_by(|a, b| a.0.cmp(&b.0));
        TableMemOid {
            rows: row_data,
            default_row,
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
                ObjectSyntax::Simple(os) => match os {
                    SimpleSyntax::Integer(i) => {
                        let iopt = i.to_i64().unwrap();
                        let iu32: u32 = iopt.try_into().unwrap();
                        ret.push(iu32);
                    }
                    SimpleSyntax::String(s) => {
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
                    SimpleSyntax::ObjectId(o) => {
                        if !implied_last || n < icols.len() - 1 {
                            let ol: u32 = o.len().try_into().unwrap();
                            ret.push(ol);
                        }
                        for ui32 in o.iter().copied() {
                            ret.push(ui32);
                        }
                    }
                },
                _ => {
                    // Could be address, which I haven't met yet
                    panic!("Unsupported type in index construction")
                }
            }
        }
        ret
    }

    fn suffix(&self, oid: ObjectIdentifier) -> Vec<u32> {
        let base_len = self.base.len();
        if oid.len() > base_len {
            oid.to_vec()[base_len..].to_vec()
        } else {
            vec![]
        }
    }

    fn row_from_index(&self, idx: &[u32]) -> Vec<ObjectSyntax> {
        let mut row: Vec<ObjectSyntax> = vec![];
        let mut idx_idx = 0;
        let num_idx_cols = self.index_cols.len();
        // First populate with defaults
        for item in &self.default_row {
            row.push(item.clone());
        }
        // Now, overwrite index columns
        for (n, index_column_number) in self.index_cols.iter().enumerate() {
            let col = self.otypes[*index_column_number - 1];
            match col {
                OType::Integer => {
                    row[*index_column_number - 1] =
                        ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(idx[idx_idx])));
                    idx_idx += 1;
                }
                OType::String => {
                    let mut text: Vec<u8> = vec![];
                    if self.implied_last && n == num_idx_cols - 1 {
                        // Then we just use all the remaining entries
                        for itemp in &idx[idx_idx..] {
                            let item = *itemp;
                            text.push(item.try_into().unwrap());
                        }
                    } else {
                        let slen: usize = idx[idx_idx].try_into().unwrap();
                        idx_idx += 1;
                        for itemp in &idx[idx_idx..(idx_idx + slen)] {
                            let item = *itemp;
                            text.push(item.try_into().unwrap());
                        }
                    }
                    row[*index_column_number - 1] = ObjectSyntax::Simple(SimpleSyntax::String(
                        OctetString::copy_from_slice(&text),
                    ));
                }
                OType::ObjectId => {
                    let mut arc: Vec<u32> = vec![];
                    if self.implied_last && n == num_idx_cols - 1 {
                        // Then we just use all the remaining entries
                        for itemp in &idx[idx_idx..] {
                            let item = *itemp;
                            arc.push(item);
                        }
                    } else {
                        let slen: usize = idx[idx_idx].try_into().unwrap();
                        idx_idx += 1;
                        for itemp in &idx[idx_idx..(idx_idx + slen)] {
                            let item = *itemp;
                            arc.push(item);
                        }
                    }
                    row[*index_column_number - 1] = ObjectSyntax::Simple(SimpleSyntax::ObjectId(
                        ObjectIdentifier::new(arc).unwrap().to_owned(),
                    ));
                }
                _ => {
                    // Could be address, which I haven't met yet
                    panic!("Unsupported type in row construction from index")
                }
            }
        }
        // Mark row as not ready
        for (n, otype) in self.otypes.iter().enumerate() {
            if *otype == OType::RowStatus {
                row[n] = ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(
                    ROW_STATUS_NOT_READY,
                )));
            }
        }
        // Further set operations will change various columns, and eventually
        // set the RowStatus to Active or Not In Service
        row
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
        let suffix = self.suffix(oid.clone());
        let mut col: usize = if suffix.len() < 3 {
            1 + self
                .access
                .iter()
                .position(|p| {
                    *p == Access::ReadOnly || *p == Access::ReadWrite || *p == Access::ReadCreate
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
            let res = self.rows.binary_search_by(|a| a.0.cmp(&suffix[2..].to_vec()));
            match res {
                Ok(idx) => { if idx < self.rows.len() -1 {
                        let (next_index, next_row) = &self.rows[idx + 1];
                        let value = VarBindValue::Value(next_row[col - 1].clone());
                        let name = self.make_oid(col, next_index);
                        return Ok(VarBind { name, value });
                } else if col < self.cols {
                        //  FIXME - need to skip non readable columns
                        col += 1;
                        let value = VarBindValue::Value(self.rows[0].1[col - 1].clone());
                        let name = self.make_oid(col, &self.rows[0].0);
                        return Ok(VarBind { name, value });
                    }
            },
                Err(insert_point) => {if insert_point < self.rows.len() {
                        let (next_index, next_row) = &self.rows[insert_point];
                        let value = VarBindValue::Value(next_row[col - 1].clone());
                        let name = self.make_oid(col, next_index);
                        return Ok(VarBind { name, value });
                } else if col < self.cols {
                        //  FIXME - need to skip non readable columns
                        col += 1;
                        let value = VarBindValue::Value(self.rows[0].1[col - 1].clone());
                        let name = self.make_oid(col, &self.rows[0].0);
                        return Ok(VarBind { name, value });
                    }}
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
    fn set(&mut self, oid: ObjectIdentifier, value: VarBindValue) -> Result<VarBindValue, OidErr> {
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
        let mut delete_me = false;
        let mut delete_idx: usize = 0;
        for row in &mut self.rows {
            if index == row.0 {
                if let VarBindValue::Value(new_value) = value.clone() {
                    if check_type(self.otypes[col - 1], &new_value) {
                        if self.otypes[col - 1] == OType::RowStatus {
                            if new_value
                                == ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(
                                    ROW_STATUS_DESTROY,
                                )))
                            {
                                delete_me = true;
                                break;
                            } else if new_value
                                == ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(
                                    ROW_STATUS_ACTIVE,
                                )))
                                || new_value
                                    == ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(
                                        ROW_STATUS_NOT_IN_SERVICE,
                                    )))
                            {
                                return Ok(value);
                            } else {
                                return Err(OidErr::WrongType);
                            }
                        } else {
                            row.1[col - 1] = new_value;
                            return Ok(value);
                        }
                    } else {
                        return Err(OidErr::WrongType);
                    }
                }
            }
            delete_idx += 1;
        }
        if delete_me {
            self.rows.remove(delete_idx);
            return Ok(value);
        }
        // No existing row matches. So either it is a row creation request
        // or an error.
        if let VarBindValue::Value(new_value) = value.clone() {
            if self.otypes[col - 1] == OType::RowStatus {
                if new_value
                    == ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(
                        ROW_STATUS_CREATE_AND_WAIT,
                    )))
                {
                    let row = self.row_from_index(index);
                    self.add_row(&row);
                    return Ok(value);
                }
                if new_value
                    == ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(
                        ROW_STATUS_CREATE_AND_GO,
                    )))
                {
                    warn!["CreateAndGo not supported"];
                    return Err(OidErr::WrongType);
                }
            }
        }
        Err(OidErr::NoSuchInstance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::{Access, OidErr, TableMemOid};
    use rasn::types::{Integer, ObjectIdentifier};
    use rasn_smi::v2::{ObjectSyntax, SimpleSyntax};
    use rasn_snmp::v3::VarBindValue;

    fn simple_from_int(value: i32) -> ObjectSyntax {
        ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(value)))
    }

    fn simple_from_str(value: &[u8]) -> ObjectSyntax {
        ObjectSyntax::Simple(SimpleSyntax::String(OctetString::copy_from_slice(value)))
    }

    const ARC2: [u32; 2] = [1, 6];
    const ARC3: [u32; 5] = [1, 6, 1, 2, 1];

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
        let first = simple_from_str(b"abc");
        let last = simple_from_str(b"xyz");
        let blank = simple_from_str(b"");
        let s0 = simple_from_int(0);
        let s42 = simple_from_int(42);
        let s41 = simple_from_int(41);
        let s4 = simple_from_int(4);
        let s5 = simple_from_int(5);
        TableMemOid::new(
            vec![vec![first.clone(), s4.clone(), s41.clone()], vec![last.clone(), s5.clone(), s42.clone()]],
            vec![blank.clone(), s0.clone(), s0.clone()],
            3,
            &oid2,
            vec![OType::String ,OType::Integer, OType::Integer],
            vec![Access::ReadOnly, Access::ReadOnly, Access::ReadWrite],
            vec![1usize, 2usize],
            false,
        )
    }
    #[test]
    fn tab_get_test() {
        let tab = tab_fixture();
        let oid2: ObjectIdentifier = ObjectIdentifier::new(&ARC2).unwrap();
        let res = tab.get(oid2);
        assert_eq!(res, Err(OidErr::NoSuchInstance));

        let o3 = ObjectIdentifier::new(&[1, 6, 1, 2, 3, 120, 121, 122, 5]).unwrap();
        let res = tab.get(o3);
        assert!(res.is_ok());
        let s5 = simple_from_int(5);
        assert_eq!(res.unwrap(), VarBindValue::Value(s5));
        let o4 = ObjectIdentifier::new(&[1, 6, 1, 3, 3, 120, 121, 122, 5]).unwrap();
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
        let o3 = ObjectIdentifier::new(&[1, 6, 1, 1]).unwrap();
        let res = tab.get_next(o3);
        assert!(res.is_ok());
        let vb = res.unwrap();
        let o4 = ObjectIdentifier::new(&[1, 6, 1, 1, 3, 97, 98, 99, 4]).unwrap();
        assert_eq!(vb.name, o4);
        let o4 = ObjectIdentifier::new(&[1, 6, 1, 1, 5]).unwrap();
        let res = tab.get_next(o4);
        assert!(res.is_ok());
        let vb = res.unwrap();
        let o5 = ObjectIdentifier::new(&[1, 6, 1, 2, 4]).unwrap();
     //   assert_eq!(vb.name, o5);
        assert_eq!(vb.value, VarBindValue::Value(simple_from_int(4)));
        let res = tab.get_next(o5);
        assert!(res.is_ok());
        let s41 = simple_from_int(41);
        let vb = res.unwrap();
        assert_eq!(vb.value, VarBindValue::Value(s41));
        let ol = ObjectIdentifier::new(&[1, 6, 1, 3, 5]).unwrap();
        let res = tab.get_next(ol);
        assert!(res.is_err());
    }

    #[test]
    fn test_add_row() {
        let mut tab = tab_fixture();
        assert_eq!(tab.rows.len(), 2);
        let s6 = simple_from_int(6);
        let s37 = simple_from_int(37);
        let row = vec![s6, s37];
        tab.add_row(&row);
        assert_eq!(tab.rows.len(), 3);
    }

    #[test]
    fn test_create_and_wait() {
        let oid2: ObjectIdentifier = ObjectIdentifier::new(&ARC2).unwrap();
        let oid3: ObjectIdentifier = ObjectIdentifier::new(&ARC3).unwrap();
        let s1 = simple_from_int(1);
        let nr = simple_from_int(4);
        let s5 = simple_from_int(5);
        let mut tab = TableMemOid::new(
            vec![],
            vec![s1.clone(), nr.clone()],
            2,
            &oid2,
            vec![OType::Integer, OType::RowStatus],
            vec![Access::ReadOnly, Access::ReadWrite],
            vec![1usize],
            false,
        );
        assert_eq!(tab.rows.len(), 0);
        let set_res = tab.set(oid3.clone(), VarBindValue::Value(s5.clone()));
        assert!(set_res.is_ok());
        assert_eq!(tab.rows.len(), 1);
        let set_res = tab.set(oid3.clone(), VarBindValue::Value(s1.clone()));
        assert!(set_res.is_ok());
        assert_eq!(tab.rows.len(), 1);
        let set_res = tab.set(oid3.clone(), VarBindValue::Value(nr.clone()));
        assert_eq!(set_res, Err(OidErr::WrongType))
    }
}
