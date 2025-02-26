use rasn::types::ObjectIdentifier;
/// Type used to hold mapping between ObjectIdentifiers and instances
/// that support OidKeep
///
/// This simplistic implementation uses a sorted vector of tuples of OID and T
///
/// You could use a Btree, but search is still O(logN)
/// Hashmap has lookup in O(1) but makes next_oid lookups harder
///
/// Trie might be worth trying in the future, as lookups are O(1), but as most MIBs are small,
/// logN is about 5 or 6 typically, so the speed up is modest, and real back end operations
///  like system calls are vastly slower.
pub struct OidMap<'a, T> {
    store: Vec<(&'a ObjectIdentifier, &'a mut T)>,
}

impl<'a, T> OidMap<'a, T> {
    pub fn new() -> Self {
        let store: Vec<(&ObjectIdentifier, &mut T)> = vec![];
        OidMap { store }
    }

    pub fn push(&mut self, arg: (&'a ObjectIdentifier, &'a mut T)) {
        self.store.push(arg);
    }

    pub fn sort(&mut self) {
        self.store.sort_by(|a, b| a.0.cmp(b.0));
    }

    pub fn search(&self, oid: &ObjectIdentifier) -> Result<usize, usize> {
        self.store.binary_search_by(|a| a.0.cmp(oid))
    }

    pub fn idx(&mut self, i: usize) -> &mut T {
        self.store[i].1
    }

    pub fn oid(&self, i: usize) -> &ObjectIdentifier {
        self.store[i].0
    }

    pub fn len(&self) -> usize {
        self.store.len()
    }

    pub fn is_empty(&self) -> bool {
        self.store.len() == 0
    }
}

impl<T> Default for OidMap<'_, T> {
    fn default() -> Self {
        Self::new()
    }
}

// FIXME Tests!
