//! One budget for everything an object can cost, shared by every assembler that is given
//! it. More assemblers do not get more of it, and each takes a [`Session`] to exist, so
//! their tables are bounded as well.
//!
//! Nothing is counted on trust. A [`Hold`] or a [`Work`] is the reservation, and dropping
//! it is the only way back, so a success, a rejection, an expiry and an unwind all return
//! the same way.
//!
//! A budget can sit inside a shared one ([`Budget::within`]). Every reservation then counts
//! in both and goes back to both, so limits of one session stand and the sum of many
//! sessions has a limit of its own. Taking from both is not atomic and does not need to
//! be: nothing is held across the two, and a refusal from the second gives the first back.
//!
//! These bound what is declared to them. They are not a bound on process memory: the
//! datagram a caller read, the maps here, queues and allocator slack are all outside.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Assemblers and bridges alive at once. Each brings tables of its own, whose sizes
    /// are bounded per session and are not counted in bytes here.
    pub max_sessions: usize,
    /// Open objects.
    pub max_objects: usize,
    /// Shards of open objects, and contents not yet given up.
    pub max_held_bytes: usize,
    /// Decodes running at once, together.
    pub max_work_bytes: usize,
    /// Objects on a spare shelf. No normal object ever waits for these.
    pub max_spare_objects: usize,
    /// Their shards and slot lists.
    pub max_spare_bytes: usize,
}

/// A limit of zero admits nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidLimits(pub &'static str);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Sessions,
    Objects,
    HeldBytes,
    WorkBytes,
    /// More than the limits could ever give, so waiting does not help.
    NeverFits,
    Spares,
    /// This budget had room, and the budget it sits inside did not.
    Shared,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Used {
    pub sessions: usize,
    pub objects: usize,
    pub held_bytes: usize,
    pub work_bytes: usize,
    pub spare_objects: usize,
    pub spare_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct Budget {
    limits: Limits,
    used: Arc<Mutex<Used>>,
    shared: Option<Box<Budget>>,
}

impl Budget {
    pub fn new(limits: Limits) -> Result<Self, InvalidLimits> {
        if limits.max_sessions == 0 {
            return Err(InvalidLimits("max_sessions"));
        }
        if limits.max_objects == 0 {
            return Err(InvalidLimits("max_objects"));
        }
        if limits.max_held_bytes == 0 {
            return Err(InvalidLimits("max_held_bytes"));
        }
        if limits.max_work_bytes == 0 {
            return Err(InvalidLimits("max_work_bytes"));
        }
        if limits.max_spare_objects == 0 {
            return Err(InvalidLimits("max_spare_objects"));
        }
        if limits.max_spare_bytes == 0 {
            return Err(InvalidLimits("max_spare_bytes"));
        }
        Ok(Self {
            limits,
            used: Arc::default(),
            shared: None,
        })
    }

    /// A budget of its own, every reservation of which also counts in `shared`.
    pub fn within(limits: Limits, shared: &Budget) -> Result<Self, InvalidLimits> {
        Ok(Self {
            shared: Some(Box::new(shared.clone())),
            ..Self::new(limits)?
        })
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    // Reservations return from `Drop`, which can run while unwinding.
    fn lock(&self) -> MutexGuard<'_, Used> {
        self.used.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn used(&self) -> Used {
        *self.lock()
    }

    pub fn session(&self) -> Result<Session, Refusal> {
        {
            let mut used = self.lock();
            if used.sessions >= self.limits.max_sessions {
                return Err(Refusal::Sessions);
            }
            used.sessions += 1;
        }
        let mut session = Session {
            budget: self.clone(),
            _shared: None,
        };
        if let Some(shared) = &self.shared {
            session._shared = Some(Box::new(shared.session()?));
        }
        Ok(session)
    }

    /// One open object and its bytes, all or nothing.
    pub fn hold(&self, bytes: usize) -> Result<Hold, Refusal> {
        if bytes > self.limits.max_held_bytes {
            return Err(Refusal::NeverFits);
        }
        {
            let mut used = self.lock();
            if used.objects >= self.limits.max_objects {
                return Err(Refusal::Objects);
            }
            if used.held_bytes + bytes > self.limits.max_held_bytes {
                return Err(Refusal::HeldBytes);
            }
            used.objects += 1;
            used.held_bytes += bytes;
        }
        let mut hold = Hold {
            budget: self.clone(),
            bytes,
            open: true,
            shared: None,
        };
        if let Some(shared) = &self.shared {
            let inner = shared.hold(bytes).map_err(|_| Refusal::Shared)?;
            hold.shared = Some(Box::new(inner));
        }
        Ok(hold)
    }

    /// A place on a spare shelf, and its first bytes.
    pub fn shelve(&self, bytes: usize) -> Result<Shelved, Refusal> {
        {
            let mut used = self.lock();
            if used.spare_objects >= self.limits.max_spare_objects
                || used.spare_bytes + bytes > self.limits.max_spare_bytes
            {
                return Err(Refusal::Spares);
            }
            used.spare_objects += 1;
            used.spare_bytes += bytes;
        }
        let mut shelved = Shelved {
            budget: self.clone(),
            bytes,
            shared: None,
        };
        if let Some(shared) = &self.shared {
            shelved.shared = Some(Box::new(shared.shelve(bytes)?));
        }
        Ok(shelved)
    }

    pub fn work(&self, bytes: usize) -> Result<Work, Refusal> {
        if bytes > self.limits.max_work_bytes {
            return Err(Refusal::NeverFits);
        }
        {
            let mut used = self.lock();
            if used.work_bytes + bytes > self.limits.max_work_bytes {
                return Err(Refusal::WorkBytes);
            }
            used.work_bytes += bytes;
        }
        let mut work = Work {
            budget: self.clone(),
            bytes,
            _shared: None,
        };
        if let Some(shared) = &self.shared {
            work._shared = Some(Box::new(shared.work(bytes).map_err(|_| Refusal::Shared)?));
        }
        Ok(work)
    }
}

/// One assembler's or bridge's place.
#[derive(Debug)]
#[must_use = "dropping a session gives its place back"]
pub struct Session {
    budget: Budget,
    _shared: Option<Box<Session>>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.budget.lock().sessions -= 1;
    }
}

/// An open object's place and bytes, then a decoded object's content.
#[derive(Debug)]
#[must_use = "dropping a hold returns its bytes"]
pub struct Hold {
    budget: Budget,
    bytes: usize,
    open: bool,
    shared: Option<Box<Hold>>,
}

impl Hold {
    /// The object is decoded: it stops counting as open, and only `bytes` stay held.
    pub(crate) fn settle(&mut self, bytes: usize) {
        let mut used = self.budget.lock();
        used.held_bytes -= self.bytes - bytes;
        used.objects -= 1;
        drop(used);
        self.bytes = bytes;
        self.open = false;
        if let Some(shared) = &mut self.shared {
            shared.settle(bytes);
        }
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        let mut used = self.budget.lock();
        used.held_bytes -= self.bytes;
        used.objects -= usize::from(self.open);
    }
}

/// An object's place on a spare shelf and the bytes it has there.
#[derive(Debug)]
#[must_use = "dropping this empties the place"]
pub struct Shelved {
    budget: Budget,
    bytes: usize,
    shared: Option<Box<Shelved>>,
}

impl Shelved {
    pub(crate) fn grow(&mut self, bytes: usize) -> Result<(), Refusal> {
        let mut used = self.budget.lock();
        if used.spare_bytes + bytes > self.budget.limits.max_spare_bytes {
            return Err(Refusal::Spares);
        }
        used.spare_bytes += bytes;
        drop(used);
        if let Some(shared) = &mut self.shared
            && let Err(refusal) = shared.grow(bytes)
        {
            self.budget.lock().spare_bytes -= bytes;
            return Err(refusal);
        }
        self.bytes += bytes;
        Ok(())
    }
}

impl Drop for Shelved {
    fn drop(&mut self) {
        let mut used = self.budget.lock();
        used.spare_bytes -= self.bytes;
        used.spare_objects -= 1;
    }
}

/// The bytes one decode is allowed, for as long as it runs.
#[derive(Debug)]
#[must_use = "dropping this ends the reservation"]
pub struct Work {
    budget: Budget,
    bytes: usize,
    _shared: Option<Box<Work>>,
}

impl Drop for Work {
    fn drop(&mut self) {
        self.budget.lock().work_bytes -= self.bytes;
    }
}
