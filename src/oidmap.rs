//! Type used to hold mapping between ObjectIdentifiers and instances that support OidKeep.
//!
//! This simplistic implementation uses a sorted vector of tuples of OID and T
//!
//! You could use a Btree, but search is still O(logN)
//! Hashmap has lookup in O(1) but makes next_oid lookups harder
//!
//! Trie might be worth trying in the future, as lookups are O(1), but as most MIBs are small,
//! logN is about 5 or 6 typically, so the speed up is modest, and real back end operations
//!  like system calls are vastly slower.
//!
use crate::keeper::OidKeeper;
use log::info;
use rasn::types::ObjectIdentifier;

/// Mapping between OID and trait objects that keep the associated data.
pub struct OidMap {
    store: Vec<(ObjectIdentifier, Box<dyn OidKeeper>)>,
}

impl OidMap {
    /// Return a new empty OidMap
    pub fn new() -> Self {
        let store: Vec<(ObjectIdentifier, Box<dyn OidKeeper>)> = vec![];
        OidMap { store }
    }

    /// Insert OID and associated trait object.
    pub fn push(&mut self, oid: ObjectIdentifier, arg: Box<dyn OidKeeper>) {
        self.store.push((oid, arg));
    }

    /// Sort into OID order, so binary search will work.
    ///
    /// Agent does this just before it enters its read loop
    pub fn sort(&mut self) {
        self.store.sort_by(|a, b| a.0.cmp(&b.0));
        info!("Sorted");
    }

    /// Binary search for trait object associated with oid, or insert point if not exact match
    pub fn search(&self, oid: &ObjectIdentifier) -> Result<usize, usize> {
        self.store.binary_search_by(|a| {
            let al = a.0.len();
            let b = if oid.len() > al {
                oid.get(0..al).unwrap()
            } else {
                oid
            };
            //let ob = &ObjectIdentifier::new(b).unwrap();
            a.0.to_vec().cmp(&b.to_vec())
        })
    }

    /// Return trait object that owns next key after oid, if found.
    pub fn search_next(&mut self, oid: &ObjectIdentifier) -> Option<&mut Box<dyn OidKeeper>> {
        let bin_res = self.store.binary_search_by(|a| {
            let al = a.0.len();
            let b = if oid.len() > al {
                oid.get(0..al).unwrap()
            } else {
                oid
            };
            //let ob = &ObjectIdentifier::new(b).unwrap();
            a.0.to_vec().cmp(&b.to_vec())
        });
        match bin_res {
            Ok(which) => {
                if which < self.store.len() - 1 {
                    Some(&mut self.store[which + 1].1)
                } else {
                    None
                }
            }
            Err(insert_point) => {
                if insert_point < self.store.len() {
                    Some(&mut self.store[insert_point].1)
                } else {
                    None
                }
            }
        }
    }

    /// Look up trait object by integer index
    pub fn idx(&mut self, i: usize) -> &mut Box<dyn OidKeeper> {
        &mut self.store[i].1
    }

    /// Look up trait object by integer index
    pub fn oid(&self, i: usize) -> &ObjectIdentifier {
        &self.store[i].0
    }

    /// Return number of entries in store.
    ///
    /// Note that if some of these are tables, with potentially many rows,
    /// there can be many more valid oid values.
    ///
    /// Sigh.
    pub fn len(&self) -> usize {
        self.store.len()
    }

    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }
}

/// Return an empty OidMap
impl Default for OidMap {
    fn default() -> Self {
        Self::new()
    }
}

// FIXME Tests!
