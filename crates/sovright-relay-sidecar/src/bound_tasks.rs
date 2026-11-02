//! Bound blocks on tasks of their own, so that what Zebra takes its time over stops nothing on
//! the receive task. That task only starts them and hears how they ended.
//!
//! The limit is on what runs. With no room the receive task leaves blocks in their channel, and
//! behind that they wait in the client with the limits they had, so it never waits for a place.
//! A task that goes, however it goes, drops its block, and that lets a copy in.
//!
//! The gate turns away only the bytes it has at Zebra. So a copy with the bytes of a running task
//! has a place of its own, one for each task, and nothing can crowd it out: it is that task's
//! retry. Any other copy of a block under way waits in a shared room while there is room. With
//! none it goes on as it came: the gate lets a different body run alongside, at the price of a
//! Zebra call on the receive task. Whether a copy comes at all, and whether it is the block, is
//! not for this to promise.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::task::{Id, JoinSet};
use tracing::{debug, error, warn};

use sovright_relay_sidecar::config;

/// A body's exact bytes, for telling copies apart as the gate does.
pub(crate) type Body = [u8; 32];

pub(crate) fn body_of(raw: &[u8]) -> Body {
    Sha256::digest(raw).into()
}

/// How much bound work runs at once, and for how long. The defaults are research values, past
/// what a parent lookup and two Zebra calls of 30 s can take, and no setting anyone decided.
/// The sidecar config sets them (`bound_tasks_*`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct BoundTaskLimits {
    /// Tasks at once. At least one.
    pub(crate) running: usize,
    /// A timer, which acts where a task waits. Work that does not wait runs to its end first,
    /// and what a task handed to another task goes on. So this bounds what Zebra can hold up,
    /// and it is no limit on CPU time or a promise of when a task will have ended.
    pub(crate) budget: Duration,
    /// Copies in the shared room. Each is one block, so this and `running` bound their bytes.
    pub(crate) held: usize,
}

impl Default for BoundTaskLimits {
    fn default() -> Self {
        Self {
            running: config::DEFAULT_BOUND_TASKS_RUNNING,
            budget: Duration::from_secs(config::DEFAULT_BOUND_TASKS_BUDGET_SECS),
            held: config::DEFAULT_BOUND_TASKS_HELD,
        }
    }
}

impl BoundTaskLimits {
    /// The limits a config gives, checked as the config is.
    pub(crate) fn from_config(
        running: usize,
        budget_secs: u64,
        held: usize,
    ) -> Result<Self, config::ConfigError> {
        config::validate_bound_task_limits(running, budget_secs, held)?;
        Ok(Self {
            running,
            budget: Duration::from_secs(budget_secs),
            held,
        })
    }
}

/// A running task's block and body.
#[derive(Default)]
struct BoundWork {
    block: String,
    body: Body,
}

/// The tasks at work, and what each is working on. Dropped, it cancels them.
pub(crate) struct BoundTasks {
    limits: BoundTaskLimits,
    running: JoinSet<bool>,
    work: HashMap<Id, BoundWork>,
}

/// What a task came to.
pub(crate) struct BoundTaskEnd {
    pub(crate) block: String,
    body: Body,
    /// Zebra has the block from this task. Ending any other way says nothing of the block.
    pub(crate) delivered: bool,
}

impl BoundTasks {
    pub(crate) fn new(limits: BoundTaskLimits) -> Self {
        Self {
            limits,
            running: JoinSet::new(),
            work: HashMap::new(),
        }
    }

    pub(crate) fn has_room(&self) -> bool {
        self.running.len() < self.limits.running
    }

    pub(crate) fn is_idle(&self) -> bool {
        self.running.is_empty()
    }

    fn under_way(&self, block: &str) -> bool {
        self.work.values().any(|work| work.block == block)
    }

    /// The block of the task on these bytes, if one is.
    fn block_of_body(&self, body: &Body) -> Option<&str> {
        let work = self.work.values().find(|work| work.body == *body);
        work.map(|work| work.block.as_str())
    }

    pub(crate) fn spawn(
        &mut self,
        block: String,
        body: Body,
        work: impl Future<Output = bool> + Send + 'static,
    ) {
        let budget = self.limits.budget;
        let task = self.running.spawn(async move {
            let finished = tokio::time::timeout(budget, work).await;
            if finished.is_err() {
                warn!(?budget, "A bound block ran out of time");
            }
            finished.unwrap_or(false)
        });
        self.work.insert(task.id(), BoundWork { block, body });
    }

    /// The next task to end. With none running this never comes, so ask only when there is one.
    pub(crate) async fn next_end(&mut self) -> BoundTaskEnd {
        let (id, delivered) = match self.running.join_next_with_id().await {
            Some(Ok(ended)) => ended,
            Some(Err(ended)) => {
                error!(error = %ended, "A bound block's task did not finish");
                (ended.id(), false)
            }
            None => std::future::pending().await,
        };
        let BoundWork { block, body } = self.work.remove(&id).unwrap_or_default();
        BoundTaskEnd {
            block,
            body,
            delivered,
        }
    }
}

/// Where a copy waits.
pub(crate) struct Place {
    block: String,
    /// The bytes of a running task, if that is what gives it this place.
    body: Option<Body>,
}

struct Waiting<T> {
    place: Place,
    copy: T,
}

/// Copies held while a task works on their block. How that ends says what each copy is: a
/// repeat once Zebra has the block, and the next try if it does not. These never pass one for
/// each running task and the shared room.
pub(crate) struct HeldCopies<T> {
    room: usize,
    copies: VecDeque<Waiting<T>>,
}

impl<T> HeldCopies<T> {
    pub(crate) fn new(room: usize) -> Self {
        Self {
            room,
            copies: VecDeque::new(),
        }
    }

    fn has_room(&self) -> bool {
        let shared = self.copies.iter().filter(|held| held.place.body.is_none());
        shared.count() < self.room
    }

    /// Where a copy of `block` waits, if it does. `body` is its bytes, which a compact block
    /// that needs the mempool cannot say: that one counts as other bytes.
    pub(crate) fn place_for(
        &self,
        tasks: &BoundTasks,
        block: &str,
        body: Option<Body>,
    ) -> Option<Place> {
        if let Some(block) = body.and_then(|body| tasks.block_of_body(&body)) {
            let block = block.to_string();
            return Some(Place { block, body });
        }
        (tasks.under_way(block) && self.has_room()).then(|| Place {
            block: block.to_string(),
            body: None,
        })
    }

    /// A second copy of bytes that have a place is not kept: a retry needs them once.
    pub(crate) fn hold(&mut self, place: Place, copy: T) {
        let copies = &mut self.copies;
        if place.body.is_some() && copies.iter().any(|held| held.place.body == place.body) {
            debug!(block_hash = %place.block, "these bytes are waiting already; dropping a copy");
            return;
        }
        copies.push_back(Waiting { place, copy });
    }

    /// What can go now that a task has ended, in the order it came. All of a block's copies go
    /// with its last task. With others still on it, the copy of these bytes has nothing left
    /// keeping it from the gate, so it stays only if the shared room has a place for it.
    pub(crate) fn task_ended(&mut self, tasks: &BoundTasks, end: &BoundTaskEnd) -> Vec<T> {
        if !tasks.under_way(&end.block) {
            return self.take(|held| held.place.block == end.block);
        }
        if tasks.block_of_body(&end.body).is_some() {
            return Vec::new();
        }
        let room = self.has_room();
        let released = self.take(|held| held.place.body == Some(end.body) && !room);
        for held in &mut self.copies {
            if held.place.body == Some(end.body) {
                held.place.body = None;
            }
        }
        released
    }

    fn take(&mut self, wanted: impl Fn(&Waiting<T>) -> bool) -> Vec<T> {
        let (released, kept): (VecDeque<_>, _) = std::mem::take(&mut self.copies)
            .into_iter()
            .partition(wanted);
        self.copies = kept;
        released.into_iter().map(|held| held.copy).collect()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use tokio::sync::oneshot;
    use tokio::time::timeout;

    use super::*;

    const WAIT: Duration = Duration::from_secs(10);

    fn tasks(running: usize) -> BoundTasks {
        BoundTasks::new(BoundTaskLimits {
            running,
            ..Default::default()
        })
    }

    fn body(mark: u8) -> Body {
        [mark; 32]
    }

    /// Says whether it was dropped, as a block a task holds does.
    struct Held(Arc<AtomicBool>);

    impl Drop for Held {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    async fn end_of(tasks: &mut BoundTasks) -> BoundTaskEnd {
        timeout(WAIT, tasks.next_end())
            .await
            .expect("no task ended")
    }

    #[tokio::test]
    async fn tasks_fill_up_and_make_room_as_they_end() {
        let mut tasks = tasks(2);
        assert!(tasks.has_room() && tasks.is_idle());
        let (first, first_done) = oneshot::channel::<()>();
        tasks.spawn("a".into(), body(1), async move { first_done.await.is_ok() });
        assert!(tasks.has_room());
        tasks.spawn("b".into(), body(2), std::future::pending());
        assert!(!tasks.has_room(), "two are running");

        first.send(()).unwrap();
        let end = end_of(&mut tasks).await;

        assert_eq!(end.block, "a");
        assert!(end.delivered);
        assert!(tasks.has_room());
        assert!(!tasks.under_way("a"));
        assert!(tasks.under_way("b"));
    }

    #[tokio::test]
    async fn a_block_stays_under_way_until_its_last_task_ends() {
        let mut tasks = tasks(4);
        let (first, first_done) = oneshot::channel::<()>();
        tasks.spawn("a".into(), body(1), async move { first_done.await.is_ok() });
        tasks.spawn("a".into(), body(2), std::future::pending());

        first.send(()).unwrap();
        end_of(&mut tasks).await;

        assert!(tasks.under_way("a"));
    }

    /// The clock stands still until nothing else can move, so the budget is what ends this.
    #[tokio::test(start_paused = true)]
    async fn a_task_past_its_budget_ends_undelivered_and_drops_what_it_held() {
        let mut tasks = BoundTasks::new(BoundTaskLimits {
            running: 1,
            budget: Duration::from_secs(5),
            ..Default::default()
        });
        let dropped = Arc::new(AtomicBool::new(false));
        let held = Held(Arc::clone(&dropped));
        tasks.spawn("a".into(), body(1), async move {
            let _held = held;
            std::future::pending().await
        });

        let started = tokio::time::Instant::now();
        let end = end_of(&mut tasks).await;

        assert_eq!(started.elapsed(), Duration::from_secs(5));
        assert_eq!(end.block, "a");
        assert!(!end.delivered);
        assert!(dropped.load(Ordering::SeqCst));
        assert!(tasks.has_room());
        assert!(!tasks.under_way("a"));
    }

    #[tokio::test]
    async fn a_task_that_panics_ends_undelivered_and_leaves_the_rest_going() {
        let mut tasks = tasks(2);
        let dropped = Arc::new(AtomicBool::new(false));
        let held = Held(Arc::clone(&dropped));
        tasks.spawn("a".into(), body(1), async move {
            let _held = held;
            panic!("in a task");
        });
        let (other, other_done) = oneshot::channel::<()>();
        tasks.spawn("b".into(), body(2), async move { other_done.await.is_ok() });

        let end = end_of(&mut tasks).await;

        assert_eq!(end.block, "a");
        assert!(!end.delivered);
        assert!(dropped.load(Ordering::SeqCst));
        assert!(!tasks.under_way("a"));
        other.send(()).unwrap();
        assert!(end_of(&mut tasks).await.delivered);
    }

    #[tokio::test]
    async fn dropping_the_tasks_cancels_them_and_drops_what_they_held() {
        let mut tasks = tasks(1);
        let dropped = Arc::new(AtomicBool::new(false));
        let held = Held(Arc::clone(&dropped));
        let (started, has_started) = oneshot::channel::<()>();
        tasks.spawn("a".into(), body(1), async move {
            let _held = held;
            let _ = started.send(());
            std::future::pending().await
        });
        timeout(WAIT, has_started).await.unwrap().unwrap();

        drop(tasks);

        let gone = async {
            while !dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        };
        timeout(WAIT, gone).await.expect("the task stayed");
    }

    /// Tasks that go on until a test ends them, and a way to end one by its block and body.
    struct Running {
        tasks: BoundTasks,
        stops: HashMap<Body, oneshot::Sender<()>>,
    }

    impl Running {
        fn new() -> Self {
            Self {
                tasks: tasks(8),
                stops: HashMap::new(),
            }
        }

        fn start(&mut self, block: &str, mark: u8) {
            let (stop, stopped) = oneshot::channel::<()>();
            self.stops.insert(body(mark), stop);
            let work = async move { stopped.await.is_ok() };
            self.tasks.spawn(block.into(), body(mark), work);
        }

        async fn end(&mut self, mark: u8) -> BoundTaskEnd {
            self.stops.remove(&body(mark)).unwrap().send(()).unwrap();
            end_of(&mut self.tasks).await
        }
    }

    fn try_hold(held: &mut HeldCopies<i32>, tasks: &BoundTasks, copy: (&str, u8, i32)) -> bool {
        let (block, mark, value) = copy;
        let body = (mark != 0).then(|| body(mark));
        match held.place_for(tasks, block, body) {
            Some(place) => {
                held.hold(place, value);
                true
            }
            None => false,
        }
    }

    #[tokio::test]
    async fn the_shared_room_stops_at_its_limit_and_copies_go_with_their_block() {
        let mut running = Running::new();
        running.start("a", 1);
        running.start("b", 2);
        let mut held = HeldCopies::new(3);
        for copy in [("a", 0, 1), ("b", 0, 2), ("a", 0, 3)] {
            assert!(try_hold(&mut held, &running.tasks, copy));
        }
        assert!(!try_hold(&mut held, &running.tasks, ("a", 0, 4)));
        assert!(!try_hold(&mut held, &running.tasks, ("c", 0, 5)));

        let end = running.end(1).await;
        assert_eq!(held.task_ended(&running.tasks, &end), vec![1, 3]);
        assert!(try_hold(&mut held, &running.tasks, ("b", 0, 6)));
        let end = running.end(2).await;
        assert_eq!(held.task_ended(&running.tasks, &end), vec![2, 6]);
    }

    /// With the shared room gone, bytes at work still have their place, under the task's block
    /// whatever the copy claimed, and it is one place.
    #[tokio::test]
    async fn bytes_at_work_have_one_place_of_their_own() {
        let mut running = Running::new();
        running.start("a", 1);
        let mut held = HeldCopies::new(0);
        assert!(!try_hold(&mut held, &running.tasks, ("a", 2, 1)));

        for copy in [("a", 1, 2), ("claimed", 1, 3), ("a", 1, 4)] {
            assert!(try_hold(&mut held, &running.tasks, copy));
        }

        let end = running.end(1).await;
        assert_eq!(held.task_ended(&running.tasks, &end), vec![2]);
    }

    /// Other bodies on the block go on, so this one's copy stays if the shared room has it,
    /// and goes now if not. It no longer has a place of its own.
    #[tokio::test]
    async fn a_copy_gives_up_its_place_when_its_task_ends_before_the_block() {
        for (room, stays) in [(1, true), (0, false)] {
            let mut running = Running::new();
            running.start("a", 1);
            running.start("a", 2);
            let mut held = HeldCopies::new(room);
            assert!(try_hold(&mut held, &running.tasks, ("a", 1, 1)));

            let end = running.end(1).await;
            let gone = held.task_ended(&running.tasks, &end);

            assert_eq!(gone, if stays { vec![] } else { vec![1] });
            assert!(!held.has_room());
            let end = running.end(2).await;
            let rest = held.task_ended(&running.tasks, &end);
            assert_eq!(rest, if stays { vec![1] } else { vec![] });
        }
    }

    /// The same bytes on two tasks for a moment, as when one has ended and is not yet heard of.
    /// The copy keeps its place until neither is left.
    #[tokio::test]
    async fn a_copy_keeps_its_place_while_its_bytes_still_run() {
        let mut tasks = tasks(4);
        let (first, first_done) = oneshot::channel::<()>();
        let (second, second_done) = oneshot::channel::<()>();
        tasks.spawn("a".into(), body(1), async move { first_done.await.is_ok() });
        tasks.spawn(
            "a".into(),
            body(1),
            async move { second_done.await.is_ok() },
        );
        let mut held = HeldCopies::new(0);
        assert!(try_hold(&mut held, &tasks, ("a", 1, 1)));

        first.send(()).unwrap();
        let end = end_of(&mut tasks).await;
        assert!(held.task_ended(&tasks, &end).is_empty());
        second.send(()).unwrap();
        let end = end_of(&mut tasks).await;

        assert_eq!(held.task_ended(&tasks, &end), vec![1]);
    }

    /// One block with tasks overlapping for as long as anyone keeps it up, each new body with a
    /// copy. What is held stays inside one for each task and the shared room.
    #[tokio::test]
    async fn copies_stay_inside_their_bound_however_tasks_overlap() {
        const RUNNING: usize = 2;
        const ROOM: usize = 1;
        let mut running = Running::new();
        let mut held = HeldCopies::new(ROOM);
        running.start("a", 1);
        for mark in 2..=64u8 {
            running.start("a", mark);
            assert!(try_hold(
                &mut held,
                &running.tasks,
                ("a", mark, i32::from(mark))
            ));
            assert!(held.copies.len() <= RUNNING + ROOM, "{}", held.copies.len());
            let end = running.end(mark - 1).await;
            held.task_ended(&running.tasks, &end);
            assert!(held.copies.len() <= RUNNING + ROOM, "{}", held.copies.len());
        }
    }

    #[test]
    fn limits_from_a_config_are_checked() {
        assert!(BoundTaskLimits::from_config(0, 120, 4).is_err());
        assert!(BoundTaskLimits::from_config(4, 0, 4).is_err());
        let limits = BoundTaskLimits::from_config(1, 7, 0).unwrap();
        assert_eq!(
            (limits.running, limits.budget, limits.held),
            (1, Duration::from_secs(7), 0)
        );
    }
}
