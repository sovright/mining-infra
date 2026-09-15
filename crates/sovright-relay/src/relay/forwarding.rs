//! Packet ordering only. Authentication and successful-send accounting stay at
//! the socket boundary. Round-robin is opt-in: it trades earlier first packets
//! for later completion at peers that previously got the first batch.

pub(super) struct ForwardOrder {
    lengths: Vec<usize>,
    next: Vec<usize>,
    peer: usize,
    remaining: usize,
    round_robin: bool,
}
impl ForwardOrder {
    pub(super) fn new(lengths: Vec<usize>, round_robin: bool) -> Self {
        let remaining = lengths.iter().sum();
        Self {
            next: vec![0; lengths.len()],
            lengths,
            peer: 0,
            remaining,
            round_robin,
        }
    }
}
impl Iterator for ForwardOrder {
    type Item = (usize, usize);
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        while self.next[self.peer] == self.lengths[self.peer] {
            self.peer = (self.peer + 1) % self.lengths.len();
        }
        let peer = self.peer;
        let packet = self.next[peer];
        self.next[peer] += 1;
        self.remaining -= 1;
        if self.round_robin {
            self.peer = (peer + 1) % self.lengths.len();
        }
        Some((peer, packet))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn visits_every_peer_before_second_packet_and_handles_unequal_batches() {
        assert_eq!(
            ForwardOrder::new(vec![3, 0, 1, 2], true).collect::<Vec<_>>(),
            vec![(0, 0), (2, 0), (3, 0), (0, 1), (3, 1), (0, 2)]
        );
        assert_eq!(
            ForwardOrder::new(vec![2, 1], false).collect::<Vec<_>>(),
            vec![(0, 0), (0, 1), (1, 0)]
        );
        assert_eq!(ForwardOrder::new(vec![], true).count(), 0);
        assert_eq!(ForwardOrder::new(vec![0, 0], true).count(), 0);
    }
    proptest::proptest! {
        #[test]
        fn no_packet_omissions_duplicates_or_reordering(lengths in proptest::collection::vec(0usize..32, 0..16)) {
            let sequential=ForwardOrder::new(lengths.clone(),false).collect::<Vec<_>>();
            let interleaved=ForwardOrder::new(lengths.clone(),true).collect::<Vec<_>>();
            let mut sorted=interleaved.clone();sorted.sort();
            proptest::prop_assert_eq!(&sorted,&sequential);
            for (peer,len) in lengths.iter().enumerate() {
                let actual=interleaved.iter().filter(|(p,_)|*p==peer).map(|(_,i)|*i).collect::<Vec<_>>();
                proptest::prop_assert_eq!(actual,(0..*len).collect::<Vec<_>>());
            }
        }
    }
}
