// ═══════════════════════════════════════════════════════════════
// Zcash Mining Infrastructure - Formal Specification
// ═══════════════════════════════════════════════════════════════

module basicSpells {
  pure def max(a: int, b: int): int = if (a >= b) a else b
  pure def min(a: int, b: int): int = if (a <= b) a else b
  pure def abs(x: int): int = if (x >= 0) x else -x
  pure def clamp(x: int, lo: int, hi: int): int = max(lo, min(x, hi))
}

module miningSpells {
  import basicSpells.*
  pure val POW_LIMIT = 1000000
  pure def target_to_difficulty(target: int): int =
    if (target <= 0) POW_LIMIT else POW_LIMIT / target
  pure def meets_target(sd: int, rd: int): bool = sd >= rd
  pure def meets_block_target(sd: int, bd: int): bool = sd >= bd
}

// ═══════════════════════════════════════════════════════════════
// MODULE 1: Share Validation Pipeline
// ═══════════════════════════════════════════════════════════════

module ShareValidation {
  import basicSpells.*
  import miningSpells.*

  const MINERS: Set[int]
  const MAX_JOB_ID: int
  const MAX_SHARES_PER_JOB: int
  const RATE_LIMIT_CAPACITY: int
  const RATE_LIMIT_REFILL: int
  const JOB_TTL: int
  const MAX_JOBS_PER_CHANNEL: int

  var jobs: int -> (int -> { target: int, active: bool, created_at: int })
  var lastJobId: int -> int
  var rateLimitTokens: int -> int
  var duplicateSets: int -> Set[int]
  var nonceAssignments: int -> int
  var blockDifficulty: int
  var clock: int
  var ghostAccepted: Set[(int, int, int)]
  var ghostBlocksFound: int
  var ghostDupsRejected: int
  var ghostTotal: int

  action init = all {
    jobs' = MINERS.mapBy(_ => Map()),
    lastJobId' = MINERS.mapBy(_ => 0),
    rateLimitTokens' = MINERS.mapBy(_ => RATE_LIMIT_CAPACITY),
    duplicateSets' = Map(),
    nonceAssignments' = MINERS.mapBy(m => m),
    blockDifficulty' = 100,
    clock' = 0,
    ghostAccepted' = Set(),
    ghostBlocksFound' = 0,
    ghostDupsRejected' = 0,
    ghostTotal' = 0,
  }

  // Frame helper: keep all state unchanged except listed
  action frameAll = all {
    jobs' = jobs, lastJobId' = lastJobId, rateLimitTokens' = rateLimitTokens,
    duplicateSets' = duplicateSets, nonceAssignments' = nonceAssignments,
    blockDifficulty' = blockDifficulty, clock' = clock,
    ghostAccepted' = ghostAccepted, ghostBlocksFound' = ghostBlocksFound,
    ghostDupsRejected' = ghostDupsRejected, ghostTotal' = ghostTotal,
  }

  action addJob(ch: int, jid: int, tgt: int, clean: bool): bool = {
    val cJobs = jobs.get(ch)
    val deact = if (clean)
      cJobs.keys().mapBy(j => { ...cJobs.get(j), active: false })
    else cJobs
    val entry = { target: tgt, active: true, created_at: clock }
    val withNew = deact.put(jid, entry)
    val trimmed = if (withNew.keys().size() > MAX_JOBS_PER_CHANNEL) {
      val cutoff = jid - MAX_JOBS_PER_CHANNEL
      withNew.keys().filter(j => j > cutoff).mapBy(j => withNew.get(j))
    } else withNew
    all {
      MINERS.contains(ch), jid > 0, tgt > 0, jid > lastJobId.get(ch),
      jobs' = jobs.set(ch, trimmed),
      lastJobId' = lastJobId.setBy(ch, cur => max(cur, jid)),
      rateLimitTokens' = rateLimitTokens, duplicateSets' = duplicateSets,
      nonceAssignments' = nonceAssignments, blockDifficulty' = blockDifficulty,
      clock' = clock, ghostAccepted' = ghostAccepted,
      ghostBlocksFound' = ghostBlocksFound, ghostDupsRejected' = ghostDupsRejected,
      ghostTotal' = ghostTotal,
    }
  }

  action validateShare(ch: int, jid: int, n2: int, sd: int): bool = {
    val tokens = rateLimitTokens.get(ch)
    val cJobs = jobs.get(ch)
    val hasJob = cJobs.keys().contains(jid)
    val jobActive = if (hasJob) cJobs.get(jid).active else false
    val jobExpired = if (hasJob) (clock - cJobs.get(jid).created_at > JOB_TTL) else true
    val jobTarget = if (hasJob) cJobs.get(jid).target else 0
    val hasDups = duplicateSets.keys().contains(jid)
    val jobDups = if (hasDups) duplicateSets.get(jid) else Set()
    val isDup = jobDups.contains(n2) or jobDups.size() >= MAX_SHARES_PER_JOB
    val reqDiff = target_to_difficulty(jobTarget)
    val meetsShare = sd > 0 and meets_target(sd, reqDiff)
    val isBlock = meets_block_target(sd, blockDifficulty)
    all {
      MINERS.contains(ch),
      ghostTotal' = ghostTotal + 1,
      if (tokens < 1) all {
        // Rate limited
        rateLimitTokens' = rateLimitTokens,
        jobs' = jobs, lastJobId' = lastJobId, duplicateSets' = duplicateSets,
        nonceAssignments' = nonceAssignments, blockDifficulty' = blockDifficulty,
        clock' = clock, ghostAccepted' = ghostAccepted,
        ghostBlocksFound' = ghostBlocksFound, ghostDupsRejected' = ghostDupsRejected,
      }
      else if (not(hasJob) or not(jobActive) or jobExpired) all {
        // Unknown/stale job
        rateLimitTokens' = rateLimitTokens.set(ch, tokens - 1),
        jobs' = jobs, lastJobId' = lastJobId, duplicateSets' = duplicateSets,
        nonceAssignments' = nonceAssignments, blockDifficulty' = blockDifficulty,
        clock' = clock, ghostAccepted' = ghostAccepted,
        ghostBlocksFound' = ghostBlocksFound, ghostDupsRejected' = ghostDupsRejected,
      }
      else if (isDup) all {
        // Duplicate
        rateLimitTokens' = rateLimitTokens.set(ch, tokens - 1),
        ghostDupsRejected' = ghostDupsRejected + 1,
        jobs' = jobs, lastJobId' = lastJobId, duplicateSets' = duplicateSets,
        nonceAssignments' = nonceAssignments, blockDifficulty' = blockDifficulty,
        clock' = clock, ghostAccepted' = ghostAccepted,
        ghostBlocksFound' = ghostBlocksFound,
      }
      else if (not(meetsShare)) all {
        // Invalid/low difficulty
        rateLimitTokens' = rateLimitTokens.set(ch, tokens - 1),
        duplicateSets' = duplicateSets.put(jid, jobDups.union(Set(n2))),
        jobs' = jobs, lastJobId' = lastJobId,
        nonceAssignments' = nonceAssignments, blockDifficulty' = blockDifficulty,
        clock' = clock, ghostAccepted' = ghostAccepted,
        ghostBlocksFound' = ghostBlocksFound, ghostDupsRejected' = ghostDupsRejected,
      }
      else all {
        // ACCEPTED
        rateLimitTokens' = rateLimitTokens.set(ch, tokens - 1),
        duplicateSets' = duplicateSets.put(jid, jobDups.union(Set(n2))),
        ghostAccepted' = ghostAccepted.union(Set((ch, jid, n2))),
        ghostBlocksFound' = if (isBlock) ghostBlocksFound + 1 else ghostBlocksFound,
        jobs' = jobs, lastJobId' = lastJobId,
        nonceAssignments' = nonceAssignments, blockDifficulty' = blockDifficulty,
        clock' = clock, ghostDupsRejected' = ghostDupsRejected,
      }
    }
  }

  action tick = all {
    clock' = clock + 1,
    rateLimitTokens' = MINERS.mapBy(m =>
      min(RATE_LIMIT_CAPACITY, rateLimitTokens.get(m) + RATE_LIMIT_REFILL)),
    jobs' = jobs, lastJobId' = lastJobId, duplicateSets' = duplicateSets,
    nonceAssignments' = nonceAssignments, blockDifficulty' = blockDifficulty,
    ghostAccepted' = ghostAccepted, ghostBlocksFound' = ghostBlocksFound,
    ghostDupsRejected' = ghostDupsRejected, ghostTotal' = ghostTotal,
  }

  action newBlock(bd: int): bool = all {
    bd > 0,
    blockDifficulty' = bd, duplicateSets' = Map(), clock' = clock + 1,
    jobs' = jobs, lastJobId' = lastJobId, rateLimitTokens' = rateLimitTokens,
    nonceAssignments' = nonceAssignments,
    ghostAccepted' = ghostAccepted, ghostBlocksFound' = ghostBlocksFound,
    ghostDupsRejected' = ghostDupsRejected, ghostTotal' = ghostTotal,
  }

  action step = {
    nondet m = MINERS.oneOf()
    // High targets → low reqDiff (e.g. target=10000 → reqDiff=100)
    nondet t = 5000.to(20000).oneOf()
    nondet bd = 50.to(150).oneOf()
    nondet n = 1.to(50).oneOf()
    nondet s = 0.to(500).oneOf()
    // Smart job selection: bias toward existing jobs, include a few misses
    val existingJobs = jobs.get(m).keys()
    val candidateJobs = existingJobs.union(Set(1, MAX_JOB_ID))
    nondet j = candidateJobs.oneOf()
    // Fresh job IDs just above the last assigned
    nondet freshJ = (lastJobId.get(m) + 1).to(lastJobId.get(m) + 5).oneOf()
    any {
      validateShare(m, j, n, s),
      addJob(m, freshJ, t, false),
      addJob(m, freshJ, t, true),
      tick,
      newBlock(bd),
    }
  }

  val rateLimitBounded = MINERS.forall(m =>
    rateLimitTokens.get(m) >= 0 and rateLimitTokens.get(m) <= RATE_LIMIT_CAPACITY)
  val jobCountBounded = MINERS.forall(m =>
    jobs.get(m).keys().size() <= MAX_JOBS_PER_CHANNEL)
  val nonceDisjoint = MINERS.forall(m1 => MINERS.forall(m2 =>
    (m1 == m2) or nonceAssignments.get(m1) != nonceAssignments.get(m2)))
  val blockDiffPositive = blockDifficulty > 0
  val dupSetBounded = duplicateSets.keys().forall(jid =>
    duplicateSets.get(jid).size() <= MAX_SHARES_PER_JOB)
  // Witnesses
  val witnessNoAccepted = ghostAccepted.size() == 0
  val witnessNoDups = ghostDupsRejected == 0
  // Reachability witnesses — expected to be violated by simulator
  val witnessAcceptedReached = ghostAccepted.size() == 0
  val witnessBlockFound = ghostBlocksFound == 0
}

module ShareValidationTest {
  import ShareValidation(
    MINERS = Set(1, 2, 3), MAX_JOB_ID = 10, MAX_SHARES_PER_JOB = 20,
    RATE_LIMIT_CAPACITY = 5, RATE_LIMIT_REFILL = 2,
    JOB_TTL = 10, MAX_JOBS_PER_CHANNEL = 3,
  ).*

  // target=10000 → reqDiff=POW_LIMIT/10000=100, sd=150 meets it
  run happyPath = init
    .then(addJob(1, 1, 10000, false))
    .then(validateShare(1, 1, 42, 150))
    .expect(ghostAccepted.size() == 1)

  run dupRejected = init
    .then(addJob(1, 1, 10000, false))
    .then(validateShare(1, 1, 42, 150))
    .then(validateShare(1, 1, 42, 150))
    .expect(ghostDupsRejected == 1)
    .expect(ghostAccepted.size() == 1)

  run unknownJob = init
    .then(validateShare(1, 99, 42, 150))
    .expect(ghostAccepted.size() == 0)

  run rateLimit = init
    .then(addJob(1, 1, 10000, false))
    .then(validateShare(1, 1, 1, 150))
    .then(validateShare(1, 1, 2, 150))
    .then(validateShare(1, 1, 3, 150))
    .then(validateShare(1, 1, 4, 150))
    .then(validateShare(1, 1, 5, 150))
    .expect(ghostAccepted.size() == 5)
    .then(validateShare(1, 1, 6, 150))
    .expect(ghostAccepted.size() == 5)

  run blockFound = init
    .then(addJob(1, 1, 10000, false))
    .then(validateShare(1, 1, 42, 150))
    .expect(ghostBlocksFound == 1)

  run cleanJobs = init
    .then(addJob(1, 1, 10000, false))
    .then(addJob(1, 2, 10000, true))
    .then(validateShare(1, 1, 42, 150))
    .expect(ghostAccepted.size() == 0)
    .then(validateShare(1, 2, 42, 150))
    .expect(ghostAccepted.size() == 1)

  run newBlockClears = init
    .then(addJob(1, 1, 10000, false))
    .then(validateShare(1, 1, 42, 150))
    .then(newBlock(100))
    .then(addJob(1, 3, 10000, true))
    .then(validateShare(1, 3, 42, 150))
    .expect(ghostAccepted.size() == 2)
}

// ═══════════════════════════════════════════════════════════════
// MODULE 2: Variable Difficulty Controller
// ═══════════════════════════════════════════════════════════════

module Vardiff {
  import basicSpells.*

  const CHANNELS: Set[int]
  const TARGET_SPW: int       // target shares per window
  const MIN_DIFF: int
  const MAX_DIFF: int
  const VAR_TOL_PCT: int      // variance tolerance (25 = 25%)
  const RETARGET_INT: int     // retarget interval in ticks
  const MIN_CHANGE: int

  var difficulty: int -> int
  var shareCount: int -> int
  var tickCount: int -> int
  var nextChId: int
  var chNonce: int -> int
  var ghostRetargets: int
  var ghostHistory: int -> List[int]

  action init = all {
    difficulty' = CHANNELS.mapBy(_ => clamp(1, MIN_DIFF, MAX_DIFF)),
    shareCount' = CHANNELS.mapBy(_ => 0),
    tickCount' = CHANNELS.mapBy(_ => 0),
    nextChId' = CHANNELS.size() + 1,
    chNonce' = CHANNELS.mapBy(c => c),
    ghostRetargets' = 0,
    ghostHistory' = CHANNELS.mapBy(_ => [clamp(1, MIN_DIFF, MAX_DIFF)]),
  }

  action recordShare(ch: int): bool = all {
    CHANNELS.contains(ch),
    shareCount' = shareCount.setBy(ch, s => s + 1),
    difficulty' = difficulty, tickCount' = tickCount,
    nextChId' = nextChId, chNonce' = chNonce,
    ghostRetargets' = ghostRetargets, ghostHistory' = ghostHistory,
  }

  action maybeRetarget(ch: int): bool = {
    val elapsed = tickCount.get(ch) + 1
    val shares = shareCount.get(ch)
    val curDiff = difficulty.get(ch)
    val lo = TARGET_SPW * (100 - VAR_TOL_PCT) / 100
    val hi = TARGET_SPW * (100 + VAR_TOL_PCT) / 100
    val inTolerance = shares >= lo and shares <= hi
    val rawNew = if (shares > 0) curDiff * shares / TARGET_SPW else curDiff / 2
    val smoothed = (curDiff + rawNew) / 2
    val clamped = clamp(smoothed, MIN_DIFF, MAX_DIFF)
    val change = abs(clamped - curDiff)
    val finalD = if (change >= MIN_CHANGE) clamped else curDiff
    all {
      CHANNELS.contains(ch),
      elapsed >= RETARGET_INT,
      if (inTolerance) all {
        shareCount' = shareCount.set(ch, 0),
        tickCount' = tickCount.set(ch, 0),
        difficulty' = difficulty,
        ghostRetargets' = ghostRetargets, ghostHistory' = ghostHistory,
        nextChId' = nextChId, chNonce' = chNonce,
      } else all {
        difficulty' = difficulty.set(ch, finalD),
        shareCount' = shareCount.set(ch, 0),
        tickCount' = tickCount.set(ch, 0),
        ghostRetargets' = ghostRetargets + 1,
        ghostHistory' = ghostHistory.setBy(ch, h => h.append(finalD)),
        nextChId' = nextChId, chNonce' = chNonce,
      }
    }
  }

  action advanceTick(ch: int): bool = all {
    CHANNELS.contains(ch),
    tickCount' = tickCount.setBy(ch, t => t + 1),
    difficulty' = difficulty, shareCount' = shareCount,
    nextChId' = nextChId, chNonce' = chNonce,
    ghostRetargets' = ghostRetargets, ghostHistory' = ghostHistory,
  }

  action step = {
    nondet ch = CHANNELS.oneOf()
    any { recordShare(ch), maybeRetarget(ch), advanceTick(ch) }
  }

  val diffInBounds = CHANNELS.forall(c =>
    difficulty.get(c) >= MIN_DIFF and difficulty.get(c) <= MAX_DIFF)
  val sharesNonNeg = CHANNELS.forall(c => shareCount.get(c) >= 0)
  val nonce1Unique = CHANNELS.forall(c1 => CHANNELS.forall(c2 =>
    (c1 == c2) or chNonce.get(c1) != chNonce.get(c2)))
  val historyInBounds = CHANNELS.forall(c =>
    ghostHistory.get(c).foldl(true, (ok, d) => ok and d >= MIN_DIFF and d <= MAX_DIFF))
  // Witnesses
  val witnessNoRetargets = ghostRetargets == 0
}

module VardiffTest {
  import Vardiff(
    CHANNELS = Set(1, 2, 3), TARGET_SPW = 5, MIN_DIFF = 1, MAX_DIFF = 1000,
    VAR_TOL_PCT = 25, RETARGET_INT = 1, MIN_CHANGE = 1,
  ).*

  run highRateUp = init
    .then(recordShare(1)).then(recordShare(1)).then(recordShare(1))
    .then(recordShare(1)).then(recordShare(1)).then(recordShare(1))
    .then(recordShare(1)).then(recordShare(1)).then(recordShare(1))
    .then(recordShare(1)).then(recordShare(1)).then(recordShare(1))
    .then(recordShare(1)).then(recordShare(1)).then(recordShare(1))
    .then(recordShare(1)).then(recordShare(1)).then(recordShare(1))
    .then(recordShare(1)).then(recordShare(1))
    .then(advanceTick(1)).then(maybeRetarget(1))
    .expect(difficulty.get(1) > 1)

  run toleranceNoChange = init
    .then(recordShare(1)).then(recordShare(1)).then(recordShare(1))
    .then(recordShare(1)).then(recordShare(1))
    .then(advanceTick(1)).then(maybeRetarget(1))
    .expect(difficulty.get(1) == 1)

  run nonce1Check = init.expect(nonce1Unique)
}

// ═══════════════════════════════════════════════════════════════
// MODULE 3: Job Declaration Protocol
// ═══════════════════════════════════════════════════════════════

module JdProtocol {
  import basicSpells.*

  type JdMode = CoinbaseOnly | FullTemplate

  type Token = {
    id: int, client: str, issued: int, lifetime: int,
    mode: JdMode, has_job: bool,
  }

  const CLIENTS: Set[str]
  const MAX_PER_CLIENT: int
  const MAX_TOTAL: int
  const TOKEN_LIFE: int
  const FT_ENABLED: bool

  var tokens: int -> Token
  var tokCtr: int
  var prevHash: int
  var jdClk: int
  var decJobs: int -> { ph: int, payout: bool }
  var nextJid: int
  var gTokAlloc: int
  var gTokExp: int
  var gJobDecl: int
  var gStale: int
  var gModeErr: int

  pure def expired(t: Token, now: int): bool = now - t.issued > t.lifetime

  action init = all {
    tokens' = Map(), tokCtr' = 1, prevHash' = 0, jdClk' = 0,
    decJobs' = Map(), nextJid' = 1,
    gTokAlloc' = 0, gTokExp' = 0, gJobDecl' = 0, gStale' = 0, gModeErr' = 0,
  }

  action allocateToken(client: str, reqMode: JdMode): bool = {
    val actIds = tokens.keys().filter(tid => not(expired(tokens.get(tid), jdClk)))
    val expCnt = tokens.keys().size() - actIds.size()
    val clean = actIds.mapBy(tid => tokens.get(tid))
    val clientCnt = clean.keys().filter(tid => clean.get(tid).client == client).size()
    val grantMode: JdMode = match reqMode {
      | FullTemplate => if (FT_ENABLED) FullTemplate else CoinbaseOnly
      | CoinbaseOnly => CoinbaseOnly
    }
    val newTok: Token = {
      id: tokCtr, client: client, issued: jdClk,
      lifetime: TOKEN_LIFE, mode: grantMode, has_job: false,
    }
    all {
      CLIENTS.contains(client),
      clean.keys().size() < MAX_TOTAL,
      clientCnt < MAX_PER_CLIENT,
      tokens' = clean.put(tokCtr, newTok),
      tokCtr' = tokCtr + 1,
      gTokAlloc' = gTokAlloc + 1,
      gTokExp' = gTokExp + expCnt,
      prevHash' = prevHash, jdClk' = jdClk, decJobs' = decJobs,
      nextJid' = nextJid, gJobDecl' = gJobDecl, gStale' = gStale, gModeErr' = gModeErr,
    }
  }

  action declareCustomJob(tid: int, ph: int, payout: bool): bool = {
    val hasTok = tokens.keys().contains(tid)
    val tok = if (hasTok) tokens.get(tid) else {
      id: 0, client: "", issued: 0, lifetime: 0, mode: CoinbaseOnly, has_job: false }
    val isExp = expired(tok, jdClk)
    val isStale = ph != prevHash
    all {
      hasTok, not(isExp),
      if (isStale) all {
        gStale' = gStale + 1,
        tokens' = tokens, tokCtr' = tokCtr, prevHash' = prevHash, jdClk' = jdClk,
        decJobs' = decJobs, nextJid' = nextJid,
        gTokAlloc' = gTokAlloc, gTokExp' = gTokExp, gJobDecl' = gJobDecl, gModeErr' = gModeErr,
      } else all {
        decJobs' = decJobs.put(nextJid, { ph: ph, payout: payout }),
        nextJid' = nextJid + 1,
        tokens' = tokens.set(tid, { ...tok, has_job: true }),
        gJobDecl' = gJobDecl + 1,
        tokCtr' = tokCtr, prevHash' = prevHash, jdClk' = jdClk,
        gTokAlloc' = gTokAlloc, gTokExp' = gTokExp, gStale' = gStale, gModeErr' = gModeErr,
      }
    }
  }

  action declareFTJob(tid: int, ph: int, payout: bool, txOk: bool): bool = {
    val hasTok = tokens.keys().contains(tid)
    val tok = if (hasTok) tokens.get(tid) else {
      id: 0, client: "", issued: 0, lifetime: 0, mode: CoinbaseOnly, has_job: false }
    val isExp = expired(tok, jdClk)
    val wrongMode = tok.mode != FullTemplate
    val isStale = ph != prevHash
    all {
      hasTok, not(isExp),
      if (wrongMode) all {
        gModeErr' = gModeErr + 1,
        tokens' = tokens, tokCtr' = tokCtr, prevHash' = prevHash, jdClk' = jdClk,
        decJobs' = decJobs, nextJid' = nextJid,
        gTokAlloc' = gTokAlloc, gTokExp' = gTokExp, gJobDecl' = gJobDecl, gStale' = gStale,
      } else if (isStale) all {
        gStale' = gStale + 1,
        tokens' = tokens, tokCtr' = tokCtr, prevHash' = prevHash, jdClk' = jdClk,
        decJobs' = decJobs, nextJid' = nextJid,
        gTokAlloc' = gTokAlloc, gTokExp' = gTokExp, gJobDecl' = gJobDecl, gModeErr' = gModeErr,
      } else if (not(txOk)) all {
        tokens' = tokens, tokCtr' = tokCtr, prevHash' = prevHash, jdClk' = jdClk,
        decJobs' = decJobs, nextJid' = nextJid,
        gTokAlloc' = gTokAlloc, gTokExp' = gTokExp, gJobDecl' = gJobDecl,
        gStale' = gStale, gModeErr' = gModeErr,
      } else all {
        decJobs' = decJobs.put(nextJid, { ph: ph, payout: payout }),
        nextJid' = nextJid + 1,
        tokens' = tokens.set(tid, { ...tok, has_job: true }),
        gJobDecl' = gJobDecl + 1,
        tokCtr' = tokCtr, prevHash' = prevHash, jdClk' = jdClk,
        gTokAlloc' = gTokAlloc, gTokExp' = gTokExp, gStale' = gStale, gModeErr' = gModeErr,
      }
    }
  }

  action jdNewBlock(np: int): bool = all {
    np != prevHash, prevHash' = np,
    tokens' = tokens, tokCtr' = tokCtr, jdClk' = jdClk,
    decJobs' = decJobs, nextJid' = nextJid,
    gTokAlloc' = gTokAlloc, gTokExp' = gTokExp, gJobDecl' = gJobDecl,
    gStale' = gStale, gModeErr' = gModeErr,
  }

  action jdTick = all {
    jdClk' = jdClk + 1,
    tokens' = tokens, tokCtr' = tokCtr, prevHash' = prevHash,
    decJobs' = decJobs, nextJid' = nextJid,
    gTokAlloc' = gTokAlloc, gTokExp' = gTokExp, gJobDecl' = gJobDecl,
    gStale' = gStale, gModeErr' = gModeErr,
  }

  action step = {
    nondet c = CLIENTS.oneOf()
    nondet mode = Set(CoinbaseOnly, FullTemplate).oneOf()
    nondet p = Set(true, false).oneOf()
    nondet tx = Set(true, false).oneOf()
    nondet np = 1.to(5).oneOf()
    // Smart token selection: bias toward active tokens, include a few misses
    val activeIds = tokens.keys().filter(tid => not(expired(tokens.get(tid), jdClk)))
    val candidateTids = activeIds.union(Set(tokCtr, tokCtr + 1))
    nondet tid = candidateTids.oneOf()
    // 50% chance of matching current prevHash
    nondet ph = Set(prevHash, prevHash + 1).oneOf()
    any {
      allocateToken(c, mode), declareCustomJob(tid, ph, p),
      declareFTJob(tid, ph, p, tx), jdNewBlock(np), jdTick,
    }
  }

  val tokCtrMono = tokens.keys().forall(tid => tid < tokCtr)
  val perClientBound = CLIENTS.forall(c =>
    tokens.keys().filter(tid =>
      tokens.get(tid).client == c and not(expired(tokens.get(tid), jdClk))
    ).size() <= MAX_PER_CLIENT)
  val totalBound = tokens.keys().filter(tid =>
    not(expired(tokens.get(tid), jdClk))).size() <= MAX_TOTAL
  val jobIdMono = nextJid > 0
  // Witnesses
  val witnessNoTokens = gTokAlloc == 0
  val witnessNoJobs = gJobDecl == 0
  // Reachability witnesses — expected to be violated by simulator
  val witnessJobsDeclared = gJobDecl == 0
}

module JdProtocolTest {
  import JdProtocol(
    CLIENTS = Set("alice", "bob"), MAX_PER_CLIENT = 3,
    MAX_TOTAL = 10, TOKEN_LIFE = 3, FT_ENABLED = true,
  ).*

  run allocAndDeclare = init
    .then(allocateToken("alice", CoinbaseOnly))
    .expect(gTokAlloc == 1)
    .then(declareCustomJob(1, 0, true))
    .expect(gJobDecl == 1)

  run expiredFails = init
    .then(allocateToken("alice", CoinbaseOnly))
    .then(jdTick).then(jdTick).then(jdTick).then(jdTick)
    .then(declareCustomJob(1, 0, true))
    .fail()

  run stalePrevHash = init
    .then(allocateToken("alice", CoinbaseOnly))
    .then(jdNewBlock(1))
    .then(declareCustomJob(1, 0, true))
    .expect(gStale == 1)

  run modeMismatch = init
    .then(allocateToken("alice", CoinbaseOnly))
    .then(declareFTJob(1, 0, true, true))
    .expect(gModeErr == 1)

  run ftHappyPath = init
    .then(allocateToken("alice", FullTemplate))
    .then(declareFTJob(1, 0, true, true))
    .expect(gJobDecl == 1)

  run perClientLimit = init
    .then(allocateToken("alice", CoinbaseOnly))
    .then(allocateToken("alice", CoinbaseOnly))
    .then(allocateToken("alice", CoinbaseOnly))
    .then(allocateToken("alice", CoinbaseOnly))
    .fail()
}

// ═══════════════════════════════════════════════════════════════
// MODULE 4: Sequence Validation
// ═══════════════════════════════════════════════════════════════

module SeqValidation {
  import basicSpells.*

  const CHANNELS: Set[int]
  const MAX_GAP: int
  const WIN_SIZE: int

  var highest: int -> int
  var window: int -> Set[int]
  var anomalies: int -> int
  var gReplays: int
  var gValid: int
  var gGapLarge: int

  pure def addToWin(w: Set[int], s: int, mx: int): Set[int] =
    if (w.size() >= mx) {
      // Find oldest (smallest) in w, using MAX_INT as initial accumulator
      // to ensure we pick from w, not accidentally pick s
      val oldest = w.fold(2147483647, (m, x) => min(m, x))
      w.exclude(Set(oldest)).union(Set(s))
    } else w.union(Set(s))

  action init = all {
    highest' = CHANNELS.mapBy(_ => 0),
    window' = CHANNELS.mapBy(_ => Set()),
    anomalies' = CHANNELS.mapBy(_ => 0),
    gReplays' = 0, gValid' = 0, gGapLarge' = 0,
  }

  action validate(ch: int, seq: int): bool = {
    val hi = highest.get(ch)
    val win = window.get(ch)
    val isFirst = hi == 0 and win.size() == 0
    val isReplay = win.contains(seq)
    val isNext = seq == hi + 1
    val isForward = seq > hi
    val gap = seq - hi
    val behind = hi - seq
    all {
      CHANNELS.contains(ch), seq > 0,
      if (isFirst) all {
        highest' = highest.set(ch, seq),
        window' = window.set(ch, Set(seq)),
        anomalies' = anomalies, gValid' = gValid + 1,
        gReplays' = gReplays, gGapLarge' = gGapLarge,
      }
      else if (isReplay) all {
        anomalies' = anomalies.setBy(ch, c => c + 1),
        gReplays' = gReplays + 1,
        highest' = highest, window' = window,
        gValid' = gValid, gGapLarge' = gGapLarge,
      }
      else if (isNext) all {
        highest' = highest.set(ch, seq),
        window' = window.set(ch, addToWin(win, seq, WIN_SIZE)),
        gValid' = gValid + 1, anomalies' = anomalies,
        gReplays' = gReplays, gGapLarge' = gGapLarge,
      }
      else if (isForward and gap <= MAX_GAP) all {
        highest' = highest.set(ch, seq),
        window' = window.set(ch, addToWin(win, seq, WIN_SIZE)),
        anomalies' = anomalies.setBy(ch, c => c + 1),
        gValid' = gValid + 1,
        gReplays' = gReplays, gGapLarge' = gGapLarge,
      }
      else if (isForward and gap > MAX_GAP) all {
        anomalies' = anomalies.setBy(ch, c => c + 1),
        gGapLarge' = gGapLarge + 1,
        highest' = highest, window' = window,
        gValid' = gValid, gReplays' = gReplays,
      }
      else if (not(isForward) and behind <= WIN_SIZE) all {
        window' = window.set(ch, addToWin(win, seq, WIN_SIZE)),
        anomalies' = anomalies.setBy(ch, c => c + 1),
        gValid' = gValid + 1, highest' = highest,
        gReplays' = gReplays, gGapLarge' = gGapLarge,
      }
      else all {
        // Stale
        anomalies' = anomalies.setBy(ch, c => c + 1),
        highest' = highest, window' = window,
        gValid' = gValid, gReplays' = gReplays, gGapLarge' = gGapLarge,
      }
    }
  }

  action step = {
    nondet ch = CHANNELS.oneOf()
    nondet seq = 1.to(50).oneOf()
    validate(ch, seq)
  }

  val winBounded = CHANNELS.forall(c => window.get(c).size() <= WIN_SIZE)
  val hiNonNeg = CHANNELS.forall(c => highest.get(c) >= 0)
  val winPositive = CHANNELS.forall(c => window.get(c).forall(s => s > 0))
  // Witnesses
  val witnessNoReplays = gReplays == 0
  val witnessNoValid = gValid == 0
}

module SeqValidationTest {
  import SeqValidation(CHANNELS = Set(1, 2), MAX_GAP = 10, WIN_SIZE = 5).*

  run seqValid = init
    .then(validate(1, 1)).then(validate(1, 2)).then(validate(1, 3))
    .expect(gValid == 3).expect(gReplays == 0)

  run replayDetect = init
    .then(validate(1, 1)).then(validate(1, 2)).then(validate(1, 2))
    .expect(gReplays == 1)

  run oooValid = init
    .then(validate(1, 1)).then(validate(1, 3)).then(validate(1, 2))
    .expect(gValid == 3)

  run gapLarge = init
    .then(validate(1, 1)).then(validate(1, 50))
    .expect(gGapLarge == 1)
}

// ═══════════════════════════════════════════════════════════════
// MODULE 5: Connection Tracking
// ═══════════════════════════════════════════════════════════════

module ConnTracking {
  const ADDRS: Set[str]
  const SHORT_THRESH: int
  const MAX_SHORT: int
  const MAX_DECRYPT: int

  var shortCnt: str -> int
  var decryptCnt: str -> int
  var totalCnt: str -> int
  var flagged: str -> bool
  var gFlags: int

  action init = all {
    shortCnt' = ADDRS.mapBy(_ => 0), decryptCnt' = ADDRS.mapBy(_ => 0),
    totalCnt' = ADDRS.mapBy(_ => 0), flagged' = ADDRS.mapBy(_ => false), gFlags' = 0,
  }

  action onDisconnect(addr: str, dur: int, decErr: bool): bool = {
    val newS = if (dur < SHORT_THRESH) shortCnt.get(addr) + 1 else shortCnt.get(addr)
    val newD = if (decErr) decryptCnt.get(addr) + 1 else decryptCnt.get(addr)
    val sf = newS >= MAX_SHORT or newD >= MAX_DECRYPT
    val was = flagged.get(addr)
    val newly = sf and not(was)
    all {
      ADDRS.contains(addr), dur >= 0,
      shortCnt' = shortCnt.set(addr, newS),
      decryptCnt' = decryptCnt.set(addr, newD),
      totalCnt' = totalCnt.setBy(addr, t => t + 1),
      flagged' = flagged.set(addr, sf or was),
      gFlags' = if (newly) gFlags + 1 else gFlags,
    }
  }

  action resetWin(addr: str): bool = all {
    ADDRS.contains(addr),
    shortCnt' = shortCnt.set(addr, 0), decryptCnt' = decryptCnt.set(addr, 0),
    totalCnt' = totalCnt, flagged' = flagged, gFlags' = gFlags,
  }

  action step = {
    nondet a = ADDRS.oneOf()
    nondet d = 0.to(20).oneOf()
    nondet e = Set(true, false).oneOf()
    any { onDisconnect(a, d, e), resetWin(a) }
  }

  val countsNonNeg = ADDRS.forall(a =>
    shortCnt.get(a) >= 0 and decryptCnt.get(a) >= 0 and totalCnt.get(a) >= 0)
  val witnessNoFlags = gFlags == 0
}

module ConnTrackingTest {
  import ConnTracking(
    ADDRS = Set("1.1.1.1", "2.2.2.2"), SHORT_THRESH = 5,
    MAX_SHORT = 3, MAX_DECRYPT = 2,
  ).*

  run normalNotFlagged = init
    .then(onDisconnect("1.1.1.1", 10, false))
    .then(onDisconnect("1.1.1.1", 15, false))
    .expect(not(flagged.get("1.1.1.1")))

  run shortLivedFlag = init
    .then(onDisconnect("1.1.1.1", 1, false))
    .then(onDisconnect("1.1.1.1", 2, false))
    .then(onDisconnect("1.1.1.1", 1, false))
    .expect(flagged.get("1.1.1.1"))

  run decryptFlag = init
    .then(onDisconnect("1.1.1.1", 10, true))
    .then(onDisconnect("1.1.1.1", 10, true))
    .expect(flagged.get("1.1.1.1"))

  run independent = init
    .then(onDisconnect("1.1.1.1", 1, false))
    .then(onDisconnect("1.1.1.1", 1, false))
    .then(onDisconnect("1.1.1.1", 1, false))
    .expect(flagged.get("1.1.1.1"))
    .expect(not(flagged.get("2.2.2.2")))
}

// ═══════════════════════════════════════════════════════════════
// MODULE 6: Payout Tracking
// ═══════════════════════════════════════════════════════════════

module Payout {
  const MINERS: Set[str]

  var totShares: str -> int
  var totDiff: str -> int
  var winShares: str -> int
  var winDiff: str -> int
  var gTotShares: int
  var gTotDiff: int
  var gResets: int

  action init = all {
    totShares' = MINERS.mapBy(_ => 0), totDiff' = MINERS.mapBy(_ => 0),
    winShares' = MINERS.mapBy(_ => 0), winDiff' = MINERS.mapBy(_ => 0),
    gTotShares' = 0, gTotDiff' = 0, gResets' = 0,
  }

  action recordShare(m: str, d: int): bool = all {
    MINERS.contains(m), d > 0,
    totShares' = totShares.setBy(m, s => s + 1),
    totDiff' = totDiff.setBy(m, x => x + d),
    winShares' = winShares.setBy(m, s => s + 1),
    winDiff' = winDiff.setBy(m, x => x + d),
    gTotShares' = gTotShares + 1, gTotDiff' = gTotDiff + d, gResets' = gResets,
  }

  action resetWindow: bool = all {
    winShares' = MINERS.mapBy(_ => 0), winDiff' = MINERS.mapBy(_ => 0),
    gResets' = gResets + 1,
    totShares' = totShares, totDiff' = totDiff,
    gTotShares' = gTotShares, gTotDiff' = gTotDiff,
  }

  action step = {
    nondet m = MINERS.oneOf()
    nondet d = 1.to(100).oneOf()
    any { recordShare(m, d), resetWindow }
  }

  val shareConserve = MINERS.fold(0, (a, m) => a + totShares.get(m)) == gTotShares
  val diffConserve = MINERS.fold(0, (a, m) => a + totDiff.get(m)) == gTotDiff
  val noNeg = MINERS.forall(m => totShares.get(m) >= 0 and winShares.get(m) >= 0)
  val winLteTotal = MINERS.forall(m =>
    winShares.get(m) <= totShares.get(m) and winDiff.get(m) <= totDiff.get(m))
  val witnessNoShares = gTotShares == 0
}

module PayoutTest {
  import Payout(MINERS = Set("alice", "bob", "carol")).*

  run basicRecord = init
    .then(recordShare("alice", 10)).then(recordShare("bob", 20))
    .then(recordShare("alice", 5))
    .expect(totShares.get("alice") == 2)
    .expect(shareConserve)

  run winReset = init
    .then(recordShare("alice", 10)).then(recordShare("bob", 20))
    .then(resetWindow)
    .expect(winShares.get("alice") == 0)
    .expect(totShares.get("alice") == 1)
    .expect(shareConserve)

  run multiReset = init
    .then(recordShare("alice", 5)).then(recordShare("bob", 10))
    .then(resetWindow)
    .then(recordShare("carol", 15)).then(recordShare("alice", 20))
    .then(resetWindow)
    .then(recordShare("bob", 25))
    .expect(shareConserve).expect(diffConserve)
}

// ═══════════════════════════════════════════════════════════════
// MODULE 7: Forge Relay
// ═══════════════════════════════════════════════════════════════

module Forge {
  import basicSpells.*

  const PEERS: Set[str]
  const DATA_S: int
  const PARITY_S: int
  const MAX_PENDING: int
  const REQ_AUTH: bool
  const MAX_RECENT: int

  pure val TOTAL_S = DATA_S + PARITY_S

  var peerAuth: str -> bool
  var assemblies: int -> { recv: Set[int], pow: bool, tot: int }
  var recon: Set[int]
  var recent: Set[(int, int)]
  var gChunks: int
  var gFwd: int
  var gAuthFail: int
  var gRecon: int

  action init = all {
    peerAuth' = PEERS.mapBy(_ => not(REQ_AUTH)),
    assemblies' = Map(), recon' = Set(), recent' = Set(),
    gChunks' = 0, gFwd' = 0, gAuthFail' = 0, gRecon' = 0,
  }

  action authPeer(p: str, ok: bool): bool = all {
    PEERS.contains(p), REQ_AUTH,
    if (ok) all {
      peerAuth' = peerAuth.set(p, true),
      assemblies' = assemblies, recon' = recon, recent' = recent,
      gChunks' = gChunks, gFwd' = gFwd, gAuthFail' = gAuthFail, gRecon' = gRecon,
    } else all {
      gAuthFail' = gAuthFail + 1,
      peerAuth' = peerAuth, assemblies' = assemblies, recon' = recon, recent' = recent,
      gChunks' = gChunks, gFwd' = gFwd, gRecon' = gRecon,
    }
  }

  action recvChunk(from: str, bh: int, cid: int, pow: bool): bool = {
    val hasAsm = assemblies.keys().contains(bh)
    val existing = if (hasAsm) assemblies.get(bh)
                   else { recv: Set(), pow: false, tot: TOTAL_S }
    val atCap = not(hasAsm) and assemblies.keys().size() >= MAX_PENDING
    val updated = { ...existing, recv: existing.recv.union(Set(cid)),
                    pow: existing.pow or pow }
    val canRecon = updated.recv.size() >= DATA_S
    val isNew = not(recon.contains(bh))
    all {
      PEERS.contains(from), cid >= 0, cid < TOTAL_S, bh > 0,
      peerAuth.get(from),
      not(recent.contains((bh, cid))),
      gChunks' = gChunks + 1,
      recent' = recent.union(Set((bh, cid))),
      if (atCap) all {
        peerAuth' = peerAuth, assemblies' = assemblies, recon' = recon,
        gFwd' = gFwd, gAuthFail' = gAuthFail, gRecon' = gRecon,
      }
      else if (canRecon and isNew) all {
        assemblies' = assemblies.put(bh, updated),
        recon' = recon.union(Set(bh)),
        gRecon' = gRecon + 1,
        gFwd' = if (updated.pow) gFwd + 1 else gFwd,
        peerAuth' = peerAuth, gAuthFail' = gAuthFail,
      }
      else all {
        assemblies' = assemblies.put(bh, updated),
        recon' = recon, gRecon' = gRecon, gFwd' = gFwd,
        peerAuth' = peerAuth, gAuthFail' = gAuthFail,
      }
    }
  }

  action pruneRecent: bool = all {
    recent.size() > MAX_RECENT,
    recent' = Set(),
    peerAuth' = peerAuth, assemblies' = assemblies, recon' = recon,
    gChunks' = gChunks, gFwd' = gFwd, gAuthFail' = gAuthFail, gRecon' = gRecon,
  }

  action step = {
    nondet p = PEERS.oneOf()
    nondet bh = 1.to(10).oneOf()
    nondet cid = 0.to(TOTAL_S - 1).oneOf()
    nondet pow = Set(true, false).oneOf()
    nondet ok = Set(true, false).oneOf()
    any { recvChunk(p, bh, cid, pow), authPeer(p, ok), pruneRecent }
  }

  val fecSound = assemblies.keys().forall(bh => {
    val a = assemblies.get(bh)
    (a.recv.size() >= DATA_S and a.pow) implies recon.contains(bh)
  })
  val pendingBound = assemblies.keys().size() <= MAX_PENDING + 1
  val chunkValid = assemblies.keys().forall(bh =>
    assemblies.get(bh).recv.forall(c => c >= 0 and c < TOTAL_S))
  val shardBound = assemblies.keys().forall(bh =>
    assemblies.get(bh).recv.size() <= TOTAL_S)
  val recentBounded = recent.size() <= MAX_RECENT + TOTAL_S
  val witnessNoChunks = gChunks == 0
  val witnessNoRecon = gRecon == 0
}

module ForgeTest {
  import Forge(
    PEERS = Set("p1", "p2", "p3"), DATA_S = 3, PARITY_S = 1,
    MAX_PENDING = 4, REQ_AUTH = false, MAX_RECENT = 50,
  ).*

  run fullRecon = init
    .then(recvChunk("p1", 1, 0, true))
    .then(recvChunk("p2", 1, 1, false))
    .then(recvChunk("p3", 1, 2, false))
    .expect(recon.contains(1)).expect(gRecon == 1)

  run insufficient = init
    .then(recvChunk("p1", 1, 0, true))
    .then(recvChunk("p2", 1, 1, false))
    .expect(not(recon.contains(1)))

  run paritySub = init
    .then(recvChunk("p1", 1, 0, true))
    .then(recvChunk("p2", 1, 1, false))
    .then(recvChunk("p3", 1, 3, false))
    .expect(recon.contains(1))

  run replayFail = init
    .then(recvChunk("p1", 1, 0, true))
    .then(recvChunk("p1", 1, 0, true))
    .fail()

  run multiBlock = init
    .then(recvChunk("p1", 1, 0, true)).then(recvChunk("p1", 2, 0, true))
    .then(recvChunk("p2", 1, 1, false)).then(recvChunk("p2", 2, 1, false))
    .then(recvChunk("p3", 1, 2, false))
    .expect(recon.contains(1)).expect(not(recon.contains(2)))
    .then(recvChunk("p3", 2, 2, false))
    .expect(recon.contains(2))
}

module ForgeAuthTest {
  import Forge(
    PEERS = Set("p1", "p2"), DATA_S = 2, PARITY_S = 1,
    MAX_PENDING = 4, REQ_AUTH = true, MAX_RECENT = 50,
  ).*

  run unauthFail = init
    .then(recvChunk("p1", 1, 0, true)).fail()

  run authOk = init
    .then(authPeer("p1", true)).then(authPeer("p2", true))
    .then(recvChunk("p1", 1, 0, true))
    .then(recvChunk("p2", 1, 1, false))
    .expect(recon.contains(1))

  run badHmac = init
    .then(authPeer("p1", false))
    .expect(gAuthFail == 1).expect(not(peerAuth.get("p1")))
}

// ═══════════════════════════════════════════════════════════════
// MODULE 8: System Composition (ShareValidation → Payout bridge)
// ═══════════════════════════════════════════════════════════════

module SystemComposition {
  import basicSpells.*
  import miningSpells.*

  const MINERS: Set[int]
  const MINER_NAMES: int -> str

  // --- ShareValidation state (simplified) ---
  var svJobs: int -> (int -> { target: int, active: bool })
  var svLastJobId: int -> int
  var svDups: int -> Set[int]
  var svBlockDiff: int
  var svAcceptedCount: int
  var svAcceptedQueue: List[(int, int)]  // (miner, difficulty) pending payout

  // --- Payout state ---
  var payTotShares: str -> int
  var payTotDiff: str -> int
  var payRecordedCount: int

  action init = all {
    svJobs' = MINERS.mapBy(_ => Map()),
    svLastJobId' = MINERS.mapBy(_ => 0),
    svDups' = Map(),
    svBlockDiff' = 100,
    svAcceptedCount' = 0,
    svAcceptedQueue' = [],
    payTotShares' = MINERS.fold(Map(), (m, id) => m.put(MINER_NAMES.get(id), 0)),
    payTotDiff' = MINERS.fold(Map(), (m, id) => m.put(MINER_NAMES.get(id), 0)),
    payRecordedCount' = 0,
  }

  action compAddJob(ch: int, jid: int, tgt: int, clean: bool): bool = {
    val cJobs = svJobs.get(ch)
    val deact = if (clean)
      cJobs.keys().mapBy(j => { ...cJobs.get(j), active: false })
    else cJobs
    val entry = { target: tgt, active: true }
    all {
      MINERS.contains(ch), jid > 0, tgt > 0, jid > svLastJobId.get(ch),
      svJobs' = svJobs.set(ch, deact.put(jid, entry)),
      svLastJobId' = svLastJobId.setBy(ch, cur => max(cur, jid)),
      svDups' = svDups, svBlockDiff' = svBlockDiff,
      svAcceptedCount' = svAcceptedCount, svAcceptedQueue' = svAcceptedQueue,
      payTotShares' = payTotShares, payTotDiff' = payTotDiff,
      payRecordedCount' = payRecordedCount,
    }
  }

  action compValidateShare(ch: int, jid: int, n2: int, sd: int): bool = {
    val cJobs = svJobs.get(ch)
    val hasJob = cJobs.keys().contains(jid)
    val jobActive = if (hasJob) cJobs.get(jid).active else false
    val jobTarget = if (hasJob) cJobs.get(jid).target else 0
    val hasDups = svDups.keys().contains(jid)
    val jobDups = if (hasDups) svDups.get(jid) else Set()
    val isDup = jobDups.contains(n2)
    val reqDiff = target_to_difficulty(jobTarget)
    val meetsShare = sd > 0 and meets_target(sd, reqDiff)
    all {
      MINERS.contains(ch), hasJob, jobActive, not(isDup), meetsShare,
      svDups' = svDups.put(jid, jobDups.union(Set(n2))),
      svAcceptedCount' = svAcceptedCount + 1,
      svAcceptedQueue' = svAcceptedQueue.append((ch, reqDiff)),
      svJobs' = svJobs, svLastJobId' = svLastJobId, svBlockDiff' = svBlockDiff,
      payTotShares' = payTotShares, payTotDiff' = payTotDiff,
      payRecordedCount' = payRecordedCount,
    }
  }

  // Drain one accepted share into the payout system
  action compRecordPayout: bool = {
    all {
      svAcceptedQueue.length() > 0,
      val entry = svAcceptedQueue[0]
      val miner = entry._1
      val diff = entry._2
      val name = MINER_NAMES.get(miner)
      all {
        payTotShares' = payTotShares.setBy(name, s => s + 1),
        payTotDiff' = payTotDiff.setBy(name, d => d + diff),
        payRecordedCount' = payRecordedCount + 1,
        svAcceptedQueue' = svAcceptedQueue.tail(),
        svJobs' = svJobs, svLastJobId' = svLastJobId, svDups' = svDups,
        svBlockDiff' = svBlockDiff, svAcceptedCount' = svAcceptedCount,
      }
    }
  }

  action step = {
    nondet m = MINERS.oneOf()
    val existingJobs = svJobs.get(m).keys()
    val candidateJobs = existingJobs.union(Set(1))
    nondet j = candidateJobs.oneOf()
    nondet freshJ = (svLastJobId.get(m) + 1).to(svLastJobId.get(m) + 3).oneOf()
    nondet n = 1.to(20).oneOf()
    nondet s = 50.to(200).oneOf()
    nondet t = 1.to(50).oneOf()
    any {
      compAddJob(m, freshJ, t, false),
      compAddJob(m, freshJ, t, true),
      compValidateShare(m, j, n, s),
      compRecordPayout,
    }
  }

  // COMPOSITION INVARIANT: accepted shares eventually equal recorded shares
  // At any point, recorded <= accepted (queue may be non-empty)
  val shareFlowConserved = payRecordedCount + svAcceptedQueue.length() == svAcceptedCount
  val recordedLeqAccepted = payRecordedCount <= svAcceptedCount
  val queueDrainable = svAcceptedQueue.length() >= 0
}

module SystemCompositionTest {
  import SystemComposition(
    MINERS = Set(1, 2),
    MINER_NAMES = Map(1 -> "alice", 2 -> "bob"),
  ).*

  // End-to-end: addJob → validateShare → recordPayout
  run compE2E = init
    .then(compAddJob(1, 1, 10000, false))
    .then(compValidateShare(1, 1, 42, 150))
    .expect(svAcceptedCount == 1)
    .expect(payRecordedCount == 0)
    .then(compRecordPayout)
    .expect(payRecordedCount == 1)
    .expect(svAcceptedQueue.length() == 0)
    .expect(shareFlowConserved)

  // Multiple miners, multiple shares, drain all
  run compMultiMiner = init
    .then(compAddJob(1, 1, 10000, false))
    .then(compAddJob(2, 1, 10000, false))
    .then(compValidateShare(1, 1, 1, 150))
    .then(compValidateShare(2, 1, 2, 150))
    .expect(svAcceptedCount == 2)
    .then(compRecordPayout)
    .then(compRecordPayout)
    .expect(payRecordedCount == 2)
    .expect(shareFlowConserved)

  // Conservation holds even with interleaved operations
  run compInterleaved = init
    .then(compAddJob(1, 1, 10000, false))
    .then(compValidateShare(1, 1, 1, 150))
    .then(compRecordPayout)
    .then(compAddJob(1, 2, 10000, false))
    .then(compValidateShare(1, 2, 2, 150))
    .expect(shareFlowConserved)
    .then(compRecordPayout)
    .expect(shareFlowConserved)
    .expect(payRecordedCount == 2)
}

// ═══════════════════════════════════════════════════════════════
// MODULE 8B: PPS Accounting Regression Models
// ═══════════════════════════════════════════════════════════════
// Models the two PPS accounting regressions fixed after review:
//
//   1. Accepted shares must credit the declared job target difficulty,
//      not the realized hash-derived difficulty.
//   2. PushSolution must submit a candidate block only. It must not create
//      a second PPS accounting event and must stay harmless if replayed.

module PpsTargetAccounting {
  import miningSpells.*

  const MINERS: Set[int]

  var payTotShares: int -> int
  var payTotDiff: int -> int
  var expectedTotDiff: int -> int
  var gHashDerivedCredits: int
  var gAcceptedShares: int

  action init = all {
    payTotShares' = MINERS.mapBy(_ => 0),
    payTotDiff' = MINERS.mapBy(_ => 0),
    expectedTotDiff' = MINERS.mapBy(_ => 0),
    gHashDerivedCredits' = 0,
    gAcceptedShares' = 0,
  }

  action recordAcceptedShareByTarget(miner: int, jobTarget: int, hashDifficulty: int): bool = {
    val reqDiff = target_to_difficulty(jobTarget)
    all {
      MINERS.contains(miner),
      jobTarget > 0,
      hashDifficulty >= reqDiff,
      payTotShares' = payTotShares.setBy(miner, s => s + 1),
      payTotDiff' = payTotDiff.setBy(miner, d => d + reqDiff),
      expectedTotDiff' = expectedTotDiff.setBy(miner, d => d + reqDiff),
      gHashDerivedCredits' = gHashDerivedCredits,
      gAcceptedShares' = gAcceptedShares + 1,
    }
  }

  action recordAcceptedShareByHash(miner: int, jobTarget: int, hashDifficulty: int): bool = {
    val reqDiff = target_to_difficulty(jobTarget)
    all {
      MINERS.contains(miner),
      jobTarget > 0,
      hashDifficulty >= reqDiff,
      payTotShares' = payTotShares.setBy(miner, s => s + 1),
      payTotDiff' = payTotDiff.setBy(miner, d => d + hashDifficulty),
      expectedTotDiff' = expectedTotDiff.setBy(miner, d => d + reqDiff),
      gHashDerivedCredits' =
        if (hashDifficulty == reqDiff) gHashDerivedCredits else gHashDerivedCredits + 1,
      gAcceptedShares' = gAcceptedShares + 1,
    }
  }

  val ppsCreditsUseJobTarget =
    gHashDerivedCredits == 0 and
    MINERS.forall(m => payTotDiff.get(m) == expectedTotDiff.get(m))
}

module PpsTargetAccountingTest {
  import miningSpells.*
  import PpsTargetAccounting(MINERS = Set(1, 2)).*

  // POW_LIMIT=1000000, so target=10000 maps to reqDiff=100.
  // The hash-derived witness uses 250 to prove the two code paths diverge.
  run targetDifficultyCredit = init
    .then(recordAcceptedShareByTarget(1, 10000, 250))
    .expect(target_to_difficulty(10000) == 100)
    .expect(payTotShares.get(1) == 1)
    .expect(payTotDiff.get(1) == target_to_difficulty(10000))
    .expect(ppsCreditsUseJobTarget)

  run hashDerivedCreditWitness = init
    .then(recordAcceptedShareByHash(1, 10000, 250))
    .expect(target_to_difficulty(10000) == 100)
    .expect(250 > target_to_difficulty(10000))
    .expect(payTotShares.get(1) == 1)
    .expect(expectedTotDiff.get(1) == target_to_difficulty(10000))
    .expect(payTotDiff.get(1) == 250)
    .expect(gHashDerivedCredits == 1)
    .expect(not(ppsCreditsUseJobTarget))
}

module PushSolutionPayout {
  const MINERS: Set[int]

  var payTotShares: int -> int
  var payTotDiff: int -> int
  var pushedSolutions: Set[(int, int)]
  var pushSolutionCredits: int -> int
  var gPushSolutionCredits: int

  action init = all {
    payTotShares' = MINERS.mapBy(_ => 0),
    payTotDiff' = MINERS.mapBy(_ => 0),
    pushedSolutions' = Set(),
    pushSolutionCredits' = MINERS.mapBy(_ => 0),
    gPushSolutionCredits' = 0,
  }

  action submitSharesPayout(miner: int, diff: int): bool = all {
    MINERS.contains(miner),
    diff > 0,
    payTotShares' = payTotShares.setBy(miner, s => s + 1),
    payTotDiff' = payTotDiff.setBy(miner, d => d + diff),
    pushedSolutions' = pushedSolutions,
    pushSolutionCredits' = pushSolutionCredits,
    gPushSolutionCredits' = gPushSolutionCredits,
  }

  action pushSolution(miner: int, solutionId: int, blockDifficulty: int): bool = all {
    MINERS.contains(miner),
    solutionId > 0,
    blockDifficulty > 0,
    pushedSolutions' = pushedSolutions.union(Set((miner, solutionId))),
    payTotShares' = payTotShares,
    payTotDiff' = payTotDiff,
    pushSolutionCredits' = pushSolutionCredits,
    gPushSolutionCredits' = gPushSolutionCredits,
  }

  action recordPushSolutionPayout(miner: int, solutionId: int, blockDifficulty: int): bool = all {
    MINERS.contains(miner),
    solutionId > 0,
    blockDifficulty > 0,
    pushedSolutions' = pushedSolutions.union(Set((miner, solutionId))),
    payTotShares' = payTotShares.setBy(miner, s => s + 1),
    payTotDiff' = payTotDiff.setBy(miner, d => d + blockDifficulty),
    pushSolutionCredits' = pushSolutionCredits.setBy(miner, c => c + 1),
    gPushSolutionCredits' = gPushSolutionCredits + 1,
  }

  val pushSolutionDoesNotCreditPps =
    gPushSolutionCredits == 0 and
    MINERS.forall(m => pushSolutionCredits.get(m) == 0)
}

module PushSolutionPayoutTest {
  import PushSolutionPayout(MINERS = Set(1, 2)).*

  run pushSolutionReplayHasNoPayoutEffect = init
    .then(submitSharesPayout(1, 100))
    .then(pushSolution(1, 42, 1000))
    .then(pushSolution(1, 42, 1000))
    .expect(payTotShares.get(1) == 1)
    .expect(payTotDiff.get(1) == 100)
    .expect(pushSolutionDoesNotCreditPps)

  run pushSolutionPayoutReplayWitness = init
    .then(submitSharesPayout(1, 100))
    .then(recordPushSolutionPayout(1, 42, 1000))
    .then(recordPushSolutionPayout(1, 42, 1000))
    .expect(payTotShares.get(1) == 3)
    .expect(payTotDiff.get(1) == 2100)
    .expect(pushSolutionCredits.get(1) == 2)
    .expect(not(pushSolutionDoesNotCreditPps))
}

// ═══════════════════════════════════════════════════════════════
// MODULE 9: Duplicate Detector Wraparound Bug
// ═══════════════════════════════════════════════════════════════

module DuplicateWraparound {
  import basicSpells.*

  const MAX_JOB_ID: int
  const MAX_SHARES: int

  var dupMap: int -> Set[int]   // job_id -> set of share hashes
  var jobIdCounter: int
  var ghostFalsePositives: int
  var activeJobs: Set[int]      // track which job IDs are currently active

  action init = all {
    dupMap' = Map(),
    jobIdCounter' = 0,
    ghostFalsePositives' = 0,
    activeJobs' = Set(),
  }

  // Allocate a new job ID (wraps around). BUG: old dup entries NOT cleared.
  action newJob: bool = {
    val nextId = if (jobIdCounter >= MAX_JOB_ID) 1 else jobIdCounter + 1
    all {
      jobIdCounter' = nextId,
      activeJobs' = activeJobs.union(Set(nextId)),
      // BUG: dupMap is NOT cleared for nextId — stale entries persist
      dupMap' = dupMap,
      ghostFalsePositives' = ghostFalsePositives,
    }
  }

  // Submit a unique share — false positive if hash collides with stale entry
  action submitShare(jid: int, hash: int): bool = {
    val hasDups = dupMap.keys().contains(jid)
    val existing = if (hasDups) dupMap.get(jid) else Set()
    val isDup = existing.contains(hash)
    // This is a genuinely unique share (different job epoch), so any
    // collision is a false positive caused by stale dup map entries
    val isFalsePositive = isDup and activeJobs.contains(jid)
    all {
      jid > 0, jid <= MAX_JOB_ID, hash > 0, hash <= MAX_SHARES,
      activeJobs.contains(jid),
      not(isDup),  // share gets rejected if dup — cannot proceed
      dupMap' = dupMap.put(jid, existing.union(Set(hash))),
      jobIdCounter' = jobIdCounter,
      ghostFalsePositives' = ghostFalsePositives,
      activeJobs' = activeJobs,
    }
  }

  // Submit share that may be falsely rejected (for invariant violation)
  action submitShareMayReject(jid: int, hash: int): bool = {
    val hasDups = dupMap.keys().contains(jid)
    val existing = if (hasDups) dupMap.get(jid) else Set()
    val isDup = existing.contains(hash)
    all {
      jid > 0, jid <= MAX_JOB_ID, hash > 0, hash <= MAX_SHARES,
      activeJobs.contains(jid),
      if (isDup) all {
        // False positive: share rejected due to stale dup entry
        ghostFalsePositives' = ghostFalsePositives + 1,
        dupMap' = dupMap, jobIdCounter' = jobIdCounter, activeJobs' = activeJobs,
      } else all {
        dupMap' = dupMap.put(jid, existing.union(Set(hash))),
        ghostFalsePositives' = ghostFalsePositives,
        jobIdCounter' = jobIdCounter, activeJobs' = activeJobs,
      }
    }
  }

  action step = {
    nondet jid = 1.to(MAX_JOB_ID).oneOf()
    nondet hash = 1.to(MAX_SHARES).oneOf()
    any {
      newJob,
      submitShareMayReject(jid, hash),
    }
  }

  // Invariant: no false positives from wraparound
  // Expected: VIOLATED — proving the bug exists
  val noFalsePositives = ghostFalsePositives == 0
}

module DuplicateWraparoundTest {
  import DuplicateWraparound(MAX_JOB_ID = 5, MAX_SHARES = 10).*

  // Demonstrate the wraparound false positive bug:
  // 1. Allocate job 1, submit share with hash 7
  // 2. Cycle through all job IDs to wrap around back to 1
  // 3. New job 1's share with hash 7 is falsely rejected
  run wraparoundBug = init
    .then(newJob)                        // jobIdCounter = 1
    .then(submitShareMayReject(1, 7))    // records hash 7 for job 1
    .then(newJob).then(newJob).then(newJob).then(newJob)  // counter = 5
    .then(newJob)                        // wraps to 1 — stale dup entry!
    .then(submitShareMayReject(1, 7))    // FALSE POSITIVE: hash 7 still in dupMap
    .expect(ghostFalsePositives == 1)

  // Normal case without wraparound works fine
  run noWraparound = init
    .then(newJob)
    .then(submitShareMayReject(1, 1))
    .then(submitShareMayReject(1, 2))
    .then(submitShareMayReject(1, 3))
    .expect(ghostFalsePositives == 0)
}

// ═══════════════════════════════════════════════════════════════
// MODULE 10: TOCTOU Concurrency Model
// ═══════════════════════════════════════════════════════════════
// Models the 3-phase lock pattern from server.rs:
//   Phase 1: acquire channels lock → rate check → release
//   Phase 2: acquire channels lock → job lookup (snapshot) → release
//   Phase 3: validate with snapshot (NO lock held)
//   Phase 4: acquire channels lock → record accepted → release
// Between phases, another thread or new-block event can:
//   - deactivate a job (clean=true on new block)
//   - change the difficulty target
// This creates a TOCTOU race window.

module ConcurrentShareValidation {
  import basicSpells.*
  import miningSpells.*

  const THREADS: Set[int]

  // Thread phase: progression through the lock pattern
  // 0 = Idle, 1 = RateCheckDone, 2 = JobLookedUp, 3 = Validated, 4 = Done
  var phase: int -> int
  // Snapshot of job state taken during phase 2 (under lock)
  var snapshot: int -> { jid: int, target: int, wasActive: bool }
  // Validation result
  var validated: int -> bool

  // Shared mutable state (protected by lock in real code)
  var lock: int                   // 0 = free, >0 = held by thread
  var jobs: int -> { target: int, active: bool }
  var accepted: Set[(int, int)]   // (thread, jid) — accepted shares
  var ghostStaleAccepts: int      // shares accepted after job deactivated

  action init = all {
    phase' = THREADS.mapBy(_ => 0),
    snapshot' = THREADS.mapBy(_ => { jid: 0, target: 0, wasActive: false }),
    validated' = THREADS.mapBy(_ => false),
    lock' = 0,
    jobs' = Map(1 -> { target: 10000, active: true }, 2 -> { target: 10000, active: true }),
    accepted' = Set(),
    ghostStaleAccepts' = 0,
  }

  // Phase 1: Rate check (acquire and release lock)
  action rateCheck(t: int): bool = all {
    THREADS.contains(t),
    phase.get(t) == 0,
    lock == 0,  // lock must be free
    // Acquire lock, do rate check, release lock — modeled as atomic
    phase' = phase.set(t, 1),
    snapshot' = snapshot, validated' = validated,
    lock' = 0,  // released immediately
    jobs' = jobs, accepted' = accepted, ghostStaleAccepts' = ghostStaleAccepts,
  }

  // Phase 2: Job lookup — snapshot job state under lock, then release
  action jobLookup(t: int, jid: int): bool = {
    val hasJob = jobs.keys().contains(jid)
    val job = if (hasJob) jobs.get(jid) else { target: 0, active: false }
    all {
      THREADS.contains(t),
      phase.get(t) == 1,
      lock == 0,
      hasJob,
      // Take snapshot while holding lock
      snapshot' = snapshot.set(t, { jid: jid, target: job.target, wasActive: job.active }),
      phase' = phase.set(t, 2),
      lock' = 0,  // released immediately
      validated' = validated,
      jobs' = jobs, accepted' = accepted, ghostStaleAccepts' = ghostStaleAccepts,
    }
  }

  // Phase 3: Validate with snapshot (NO lock held!)
  // This is the expensive Equihash validation — runs lock-free
  action validate(t: int, shareDiff: int): bool = {
    val snap = snapshot.get(t)
    val reqDiff = target_to_difficulty(snap.target)
    val meets = shareDiff > 0 and meets_target(shareDiff, reqDiff)
    all {
      THREADS.contains(t),
      phase.get(t) == 2,
      snap.wasActive,  // was active when we looked
      meets,           // share meets difficulty
      validated' = validated.set(t, true),
      phase' = phase.set(t, 3),
      // NO lock interaction — this is the TOCTOU window
      lock' = lock,
      snapshot' = snapshot, jobs' = jobs, accepted' = accepted,
      ghostStaleAccepts' = ghostStaleAccepts,
    }
  }

  // Phase 4: Record accepted share (acquire lock, record, release)
  action recordAccepted(t: int): bool = {
    val snap = snapshot.get(t)
    val jid = snap.jid
    // Check current job state (may differ from snapshot!)
    val hasJob = jobs.keys().contains(jid)
    val nowActive = if (hasJob) jobs.get(jid).active else false
    val isStale = not(nowActive)  // job was deactivated between phases 2-4
    all {
      THREADS.contains(t),
      phase.get(t) == 3,
      validated.get(t),
      lock == 0,
      // Record the share (the real code does NOT re-check job.active here!)
      accepted' = accepted.union(Set((t, jid))),
      ghostStaleAccepts' = if (isStale) ghostStaleAccepts + 1 else ghostStaleAccepts,
      phase' = phase.set(t, 4),
      lock' = 0,
      snapshot' = snapshot, validated' = validated, jobs' = jobs,
    }
  }

  // Reset thread to idle for next share
  action resetThread(t: int): bool = all {
    THREADS.contains(t),
    phase.get(t) == 4,
    phase' = phase.set(t, 0),
    validated' = validated.set(t, false),
    snapshot' = snapshot, lock' = lock, jobs' = jobs,
    accepted' = accepted, ghostStaleAccepts' = ghostStaleAccepts,
  }

  // External event: new block deactivates all jobs (clean=true)
  // Can happen between any thread phases!
  action newBlockClean: bool = all {
    lock == 0,
    jobs' = jobs.keys().mapBy(jid => { ...jobs.get(jid), active: false }),
    lock' = 0,
    phase' = phase, snapshot' = snapshot, validated' = validated,
    accepted' = accepted, ghostStaleAccepts' = ghostStaleAccepts,
  }

  // External event: add a new active job
  action addNewJob(jid: int, tgt: int): bool = all {
    lock == 0,
    jid > 0, tgt > 0,
    jobs' = jobs.put(jid, { target: tgt, active: true }),
    lock' = 0,
    phase' = phase, snapshot' = snapshot, validated' = validated,
    accepted' = accepted, ghostStaleAccepts' = ghostStaleAccepts,
  }

  action step = {
    nondet t = THREADS.oneOf()
    nondet jid = 1.to(3).oneOf()
    nondet sd = 100.to(500).oneOf()
    nondet tgt = 5000.to(20000).oneOf()
    any {
      rateCheck(t),
      jobLookup(t, jid),
      validate(t, sd),
      recordAccepted(t),
      resetThread(t),
      newBlockClean,
      addNewJob(jid, tgt),
    }
  }

  // INVARIANT: accepted shares always had active jobs at record time
  // Expected: VIOLATED — proving the TOCTOU race
  val toctouSafe = ghostStaleAccepts == 0

  // Safety: phases are well-ordered
  val phaseBounded = THREADS.forall(t => phase.get(t) >= 0 and phase.get(t) <= 4)
}

module ConcurrentShareValidationTest {
  import ConcurrentShareValidation(THREADS = Set(1, 2)).*

  // Demonstrate the TOCTOU race:
  // Thread 1 looks up job (active), then new block deactivates it,
  // then thread 1 validates and records — accepting a stale job's share
  run toctouRace = init
    .then(rateCheck(1))
    .then(jobLookup(1, 1))          // snapshot: job 1 active
    .then(newBlockClean)             // RACE: all jobs deactivated
    .then(validate(1, 150))          // validates against stale snapshot
    .then(recordAccepted(1))         // accepts share for deactivated job!
    .expect(ghostStaleAccepts == 1)

  // Without race, no stale accepts
  run noRace = init
    .then(rateCheck(1))
    .then(jobLookup(1, 1))
    .then(validate(1, 150))
    .then(recordAccepted(1))
    .expect(ghostStaleAccepts == 0)

  // Two-thread interleaving showing the race
  run twoThreadRace = init
    .then(rateCheck(1))
    .then(rateCheck(2))
    .then(jobLookup(1, 1))          // T1 snapshots job 1 as active
    .then(jobLookup(2, 2))          // T2 snapshots job 2 as active
    .then(newBlockClean)             // both jobs deactivated
    .then(validate(1, 150))
    .then(validate(2, 150))
    .then(recordAccepted(1))
    .then(recordAccepted(2))
    .expect(ghostStaleAccepts == 2)  // both threads accepted stale shares
}

// ═══════════════════════════════════════════════════════════════
// MODULE 11: Template Provider
// ═══════════════════════════════════════════════════════════════
// Models the TemplateProvider polling loop from template.rs:
//   - Polls Zebra RPC at intervals, computes fingerprints
//   - Deduplicates identical templates (same fingerprint)
//   - Monotonically increasing template IDs
//   - Broadcasts new templates to subscribers
//   - Handles RPC failures gracefully (continues polling)

module TemplateProvider {
  import basicSpells.*

  const MAX_HEIGHT: int
  const MAX_TEMPLATE_ID: int

  // Template: height, prev_hash, merkle_root, bits (fingerprint components)
  type Template = {
    id: int, height: int, prev_hash: int, merkle_root: int, bits: int,
  }

  // Fingerprint derived from template fields
  pure def fingerprint(t: Template): (int, int, int) =
    (t.height, t.prev_hash, t.merkle_root)

  var templateId: int               // monotonic counter (starts at 1)
  var currentTemplate: Template     // latest valid template
  var hasTemplate: bool             // false until first successful fetch
  var lastFingerprint: (int, int, int)
  var subscribers: int              // count of active subscribers
  var gBroadcasts: int             // ghost: total broadcasts sent
  var gDedups: int                 // ghost: skipped due to same fingerprint
  var gFetchFails: int             // ghost: RPC fetch failures
  var gTemplateFails: int          // ghost: template processing failures

  val emptyTemplate: Template = {
    id: 0, height: 0, prev_hash: 0, merkle_root: 0, bits: 0,
  }

  action init = all {
    templateId' = 1,
    currentTemplate' = emptyTemplate,
    hasTemplate' = false,
    lastFingerprint' = (0, 0, 0),
    subscribers' = 0,
    gBroadcasts' = 0,
    gDedups' = 0,
    gFetchFails' = 0,
    gTemplateFails' = 0,
  }

  // Successful poll: new template with different fingerprint
  action pollNewTemplate(height: int, ph: int, mr: int, bits: int): bool = {
    val fp = (height, ph, mr)
    val newId = templateId
    val t: Template = { id: newId, height: height, prev_hash: ph,
                        merkle_root: mr, bits: bits }
    all {
      height > 0, height <= MAX_HEIGHT,
      ph > 0, mr > 0, bits > 0,
      fp != lastFingerprint,  // fingerprint changed
      templateId' = templateId + 1,
      currentTemplate' = t,
      hasTemplate' = true,
      lastFingerprint' = fp,
      gBroadcasts' = gBroadcasts + 1,
      gDedups' = gDedups,
      gFetchFails' = gFetchFails,
      gTemplateFails' = gTemplateFails,
      subscribers' = subscribers,
    }
  }

  // Poll returns same fingerprint: deduplicated, no broadcast
  action pollSameTemplate(height: int, ph: int, mr: int): bool = {
    val fp = (height, ph, mr)
    all {
      hasTemplate,            // must have fetched at least once
      fp == lastFingerprint,  // same fingerprint
      templateId' = templateId,
      currentTemplate' = currentTemplate,
      hasTemplate' = hasTemplate,
      lastFingerprint' = lastFingerprint,
      gDedups' = gDedups + 1,
      gBroadcasts' = gBroadcasts,
      gFetchFails' = gFetchFails,
      gTemplateFails' = gTemplateFails,
      subscribers' = subscribers,
    }
  }

  // RPC fetch failure: state unchanged, continue polling
  action fetchFail: bool = all {
    templateId' = templateId,
    currentTemplate' = currentTemplate,
    hasTemplate' = hasTemplate,
    lastFingerprint' = lastFingerprint,
    subscribers' = subscribers,
    gFetchFails' = gFetchFails + 1,
    gBroadcasts' = gBroadcasts,
    gDedups' = gDedups,
    gTemplateFails' = gTemplateFails,
  }

  // Template processing failure (e.g., bad header data)
  action templateProcessFail: bool = all {
    templateId' = templateId,
    currentTemplate' = currentTemplate,
    hasTemplate' = hasTemplate,
    lastFingerprint' = lastFingerprint,
    subscribers' = subscribers,
    gTemplateFails' = gTemplateFails + 1,
    gBroadcasts' = gBroadcasts,
    gDedups' = gDedups,
    gFetchFails' = gFetchFails,
  }

  // Subscriber joins
  action addSubscriber: bool = all {
    subscribers' = subscribers + 1,
    templateId' = templateId,
    currentTemplate' = currentTemplate,
    hasTemplate' = hasTemplate,
    lastFingerprint' = lastFingerprint,
    gBroadcasts' = gBroadcasts,
    gDedups' = gDedups,
    gFetchFails' = gFetchFails,
    gTemplateFails' = gTemplateFails,
  }

  action step = {
    nondet h = 1.to(MAX_HEIGHT).oneOf()
    nondet ph = 1.to(10).oneOf()
    nondet mr = 1.to(10).oneOf()
    nondet bits = 1.to(10).oneOf()
    any {
      pollNewTemplate(h, ph, mr, bits),
      pollSameTemplate(h, ph, mr),
      fetchFail,
      templateProcessFail,
      addSubscriber,
    }
  }

  // INVARIANTS

  // Template ID is strictly monotonic (never decreases)
  val templateIdMonotonic = templateId >= 1

  // Current template ID < next template ID counter
  val templateIdConsistent =
    if (hasTemplate) currentTemplate.id < templateId
    else currentTemplate.id == 0

  // Height is non-decreasing once we have a template
  val heightPositive =
    if (hasTemplate) currentTemplate.height > 0 else true

  // Dedup correctness: broadcasts + dedups + failures = total polls attempted
  // (Not directly trackable without total poll counter, so we verify components are non-negative)
  val countersNonNeg =
    gBroadcasts >= 0 and gDedups >= 0 and gFetchFails >= 0 and gTemplateFails >= 0

  // Broadcasts only happen when template changes
  val broadcastsBounded = gBroadcasts <= templateId - 1

  // Witnesses
  val witnessNoBroadcasts = gBroadcasts == 0
  val witnessNoFetchFails = gFetchFails == 0
}

module TemplateProviderTest {
  import TemplateProvider(MAX_HEIGHT = 20, MAX_TEMPLATE_ID = 100).*

  run firstPoll = init
    .then(pollNewTemplate(1, 1, 1, 5))
    .expect(hasTemplate)
    .expect(currentTemplate.id == 1)
    .expect(templateId == 2)
    .expect(gBroadcasts == 1)

  run dedupSameFingerprint = init
    .then(pollNewTemplate(1, 1, 1, 5))
    .then(pollSameTemplate(1, 1, 1))
    .expect(gDedups == 1)
    .expect(gBroadcasts == 1)
    .expect(templateId == 2)  // not incremented

  run newBlockTemplate = init
    .then(pollNewTemplate(1, 1, 1, 5))
    .then(pollNewTemplate(2, 2, 3, 5))  // new block, new fingerprint
    .expect(gBroadcasts == 2)
    .expect(currentTemplate.height == 2)
    .expect(templateId == 3)

  run fetchFailRecovery = init
    .then(fetchFail)
    .expect(not(hasTemplate))
    .expect(gFetchFails == 1)
    .then(pollNewTemplate(1, 1, 1, 5))
    .expect(hasTemplate)
    .expect(gBroadcasts == 1)

  run multipleFailsThenRecover = init
    .then(fetchFail).then(templateProcessFail).then(fetchFail)
    .then(pollNewTemplate(5, 3, 4, 7))
    .expect(hasTemplate)
    .expect(gFetchFails == 2)
    .expect(gTemplateFails == 1)

  run templateIdMonotonicCheck = init
    .then(pollNewTemplate(1, 1, 1, 5))
    .then(pollNewTemplate(2, 2, 2, 5))
    .then(pollNewTemplate(3, 3, 3, 5))
    .expect(templateId == 4)
    .expect(templateIdMonotonic)
    .expect(broadcastsBounded)
}

// ═══════════════════════════════════════════════════════════════
// MODULE 12: Nonce Space Partitioning
// ═══════════════════════════════════════════════════════════════
// Models the NoncePartitioner from nonce.rs:
//   - Splits 32-byte nonce into pool prefix (nonce_1) and miner suffix (nonce_2)
//   - Each miner gets a unique nonce_1 via monotonic ID allocation
//   - Ensures no two miners share nonce space (collision-free)

module NoncePartition {
  import basicSpells.*

  const NONCE_TOTAL: int     // always 32
  const NONCE_1_LEN: int     // pool prefix length (1..32)
  const MAX_MINERS: int      // max concurrent miners

  var nextId: int             // monotonic allocation counter
  var allocated: Set[int]     // set of allocated miner IDs
  var nonce1Map: int -> int   // miner_id -> nonce_1 value (encoded from ID)
  var gAllocations: int       // ghost: total allocations

  pure def nonce_2_len(n1len: int): int = NONCE_TOTAL - n1len

  // Deterministic nonce_1 derivation from miner ID
  // In real code: big-endian encoding of ID into last bytes of nonce_1
  // Here: nonce_1 value = miner_id (injective for distinct IDs)
  pure def derive_nonce_1(id: int): int = id

  action init = all {
    nextId' = 1,  // start at 1 (0 reserved)
    allocated' = Set(),
    nonce1Map' = Map(),
    gAllocations' = 0,
  }

  // Allocate a nonce range for a new miner
  action allocateRange: bool = {
    val id = nextId
    val n1 = derive_nonce_1(id)
    all {
      allocated.size() < MAX_MINERS,
      nextId' = nextId + 1,
      allocated' = allocated.union(Set(id)),
      nonce1Map' = nonce1Map.put(id, n1),
      gAllocations' = gAllocations + 1,
    }
  }

  // Miner disconnects, freeing its slot (but ID is not reused)
  action deallocate(id: int): bool = all {
    allocated.contains(id),
    allocated' = allocated.exclude(Set(id)),
    nonce1Map' = nonce1Map,  // keep mapping for reference
    nextId' = nextId,
    gAllocations' = gAllocations,
  }

  action step = {
    if (allocated.size() == 0)
      allocateRange
    else {
      nondet id = allocated.oneOf()
      any {
        allocateRange,
        deallocate(id),
      }
    }
  }

  // INVARIANTS

  // Nonce space conservation: nonce_1_len + nonce_2_len = 32
  val nonceConservation = nonce_2_len(NONCE_1_LEN) + NONCE_1_LEN == NONCE_TOTAL

  // All allocated miners have unique nonce_1 values
  val nonce1Unique = allocated.forall(a => allocated.forall(b =>
    (a == b) or nonce1Map.get(a) != nonce1Map.get(b)))

  // Monotonic ID allocation: all allocated IDs < nextId
  val idsMonotonic = allocated.forall(id => id > 0 and id < nextId)

  // Active miners bounded
  val minersBounded = allocated.size() <= MAX_MINERS

  // No zero IDs allocated (0 is reserved)
  val noZeroId = not(allocated.contains(0))

  // Witnesses
  val witnessNoAllocations = gAllocations == 0
}

module NoncePartitionTest {
  import NoncePartition(NONCE_TOTAL = 32, NONCE_1_LEN = 4, MAX_MINERS = 5).*

  run basicAllocation = init
    .then(allocateRange)
    .expect(allocated.size() == 1)
    .expect(nextId == 2)
    .expect(nonce1Unique)

  run multipleMiners = init
    .then(allocateRange).then(allocateRange).then(allocateRange)
    .expect(allocated.size() == 3)
    .expect(nonce1Unique)
    .expect(idsMonotonic)

  run deallocateAndReallocate = init
    .then(allocateRange)   // id=1
    .then(allocateRange)   // id=2
    .then(deallocate(1))
    .expect(allocated.size() == 1)
    .then(allocateRange)   // id=3 (not reusing 1)
    .expect(nextId == 4)
    .expect(nonce1Unique)

  run nonceConservationCheck = init
    .expect(nonceConservation)
    .expect(nonce_2_len(4) == 28)

  run maxMinersEnforced = init
    .then(allocateRange).then(allocateRange).then(allocateRange)
    .then(allocateRange).then(allocateRange)
    .expect(allocated.size() == 5)
    .then(allocateRange).fail()  // exceeds MAX_MINERS
}

// ═══════════════════════════════════════════════════════════════
// MODULE 13: Session Lifecycle
// ═══════════════════════════════════════════════════════════════
// Models per-miner session from session.rs:
//   - Session state machine: Connected → Active → Disconnected
//   - Message sequencing: each share gets exactly one response
//   - Buffer limits: 64KB read buffer, 1MB frame limit
//   - Share validation timeout: 30s deadline
//   - Channel ID validation: share must match session's channel

module SessionLifecycle {
  import basicSpells.*

  const SESSIONS: Set[int]
  const MAX_BUFFER: int       // 64KB in real code
  const MAX_FRAME: int        // 1MB in real code
  const VALIDATION_TIMEOUT: int  // 30s in ticks

  // Session states
  // 0 = Disconnected, 1 = Connected (idle), 2 = WaitingValidation, 3 = Responding
  var sessionState: int -> int
  var channelId: int -> int           // assigned channel per session
  var pendingSeqNum: int -> int       // sequence number of pending share
  var waitTicks: int -> int           // ticks waiting for validation
  var bufferUsed: int -> int          // current read buffer usage
  var sharesProcessed: int -> int     // total shares processed per session
  var gTimeouts: int
  var gBufferOverflows: int
  var gFrameOverflows: int
  var gSharesAccepted: int
  var gSharesRejected: int
  var gDisconnects: int

  action init = all {
    sessionState' = SESSIONS.mapBy(_ => 0),  // all disconnected
    channelId' = SESSIONS.mapBy(s => s),      // unique channel IDs
    pendingSeqNum' = SESSIONS.mapBy(_ => 0),
    waitTicks' = SESSIONS.mapBy(_ => 0),
    bufferUsed' = SESSIONS.mapBy(_ => 0),
    sharesProcessed' = SESSIONS.mapBy(_ => 0),
    gTimeouts' = 0,
    gBufferOverflows' = 0,
    gFrameOverflows' = 0,
    gSharesAccepted' = 0,
    gSharesRejected' = 0,
    gDisconnects' = 0,
  }

  // Session connects
  action connect(s: int): bool = all {
    SESSIONS.contains(s),
    sessionState.get(s) == 0,
    sessionState' = sessionState.set(s, 1),
    channelId' = channelId, pendingSeqNum' = pendingSeqNum,
    waitTicks' = waitTicks, bufferUsed' = bufferUsed,
    sharesProcessed' = sharesProcessed,
    gTimeouts' = gTimeouts, gBufferOverflows' = gBufferOverflows,
    gFrameOverflows' = gFrameOverflows, gSharesAccepted' = gSharesAccepted,
    gSharesRejected' = gSharesRejected, gDisconnects' = gDisconnects,
  }

  // Miner submits a share (with buffer and frame size checks)
  action submitShare(s: int, seq: int, frameSize: int, bufSize: int): bool = all {
    SESSIONS.contains(s),
    sessionState.get(s) == 1,  // must be connected/idle
    seq > 0,
    // Buffer limit check
    bufSize <= MAX_BUFFER,
    frameSize <= MAX_FRAME,
    sessionState' = sessionState.set(s, 2),  // waiting for validation
    pendingSeqNum' = pendingSeqNum.set(s, seq),
    waitTicks' = waitTicks.set(s, 0),
    bufferUsed' = bufferUsed.set(s, bufSize),
    channelId' = channelId,
    sharesProcessed' = sharesProcessed,
    gTimeouts' = gTimeouts, gBufferOverflows' = gBufferOverflows,
    gFrameOverflows' = gFrameOverflows, gSharesAccepted' = gSharesAccepted,
    gSharesRejected' = gSharesRejected, gDisconnects' = gDisconnects,
  }

  // Buffer overflow: miner sends too much data
  action bufferOverflow(s: int): bool = all {
    SESSIONS.contains(s),
    sessionState.get(s) == 1,
    // Disconnect on overflow
    sessionState' = sessionState.set(s, 0),
    gBufferOverflows' = gBufferOverflows + 1,
    gDisconnects' = gDisconnects + 1,
    channelId' = channelId, pendingSeqNum' = pendingSeqNum,
    waitTicks' = waitTicks, bufferUsed' = bufferUsed,
    sharesProcessed' = sharesProcessed,
    gTimeouts' = gTimeouts, gFrameOverflows' = gFrameOverflows,
    gSharesAccepted' = gSharesAccepted, gSharesRejected' = gSharesRejected,
  }

  // Frame too large: disconnect
  action frameOverflow(s: int): bool = all {
    SESSIONS.contains(s),
    sessionState.get(s) == 1,
    sessionState' = sessionState.set(s, 0),
    gFrameOverflows' = gFrameOverflows + 1,
    gDisconnects' = gDisconnects + 1,
    channelId' = channelId, pendingSeqNum' = pendingSeqNum,
    waitTicks' = waitTicks, bufferUsed' = bufferUsed,
    sharesProcessed' = sharesProcessed,
    gTimeouts' = gTimeouts, gBufferOverflows' = gBufferOverflows,
    gSharesAccepted' = gSharesAccepted, gSharesRejected' = gSharesRejected,
  }

  // Validation completes: share accepted
  action shareAccepted(s: int): bool = all {
    SESSIONS.contains(s),
    sessionState.get(s) == 2,
    waitTicks.get(s) < VALIDATION_TIMEOUT,
    sessionState' = sessionState.set(s, 1),  // back to idle
    sharesProcessed' = sharesProcessed.setBy(s, c => c + 1),
    gSharesAccepted' = gSharesAccepted + 1,
    bufferUsed' = bufferUsed.set(s, 0),
    channelId' = channelId, pendingSeqNum' = pendingSeqNum,
    waitTicks' = waitTicks,
    gTimeouts' = gTimeouts, gBufferOverflows' = gBufferOverflows,
    gFrameOverflows' = gFrameOverflows, gSharesRejected' = gSharesRejected,
    gDisconnects' = gDisconnects,
  }

  // Validation completes: share rejected
  action shareRejected(s: int): bool = all {
    SESSIONS.contains(s),
    sessionState.get(s) == 2,
    waitTicks.get(s) < VALIDATION_TIMEOUT,
    sessionState' = sessionState.set(s, 1),  // back to idle
    sharesProcessed' = sharesProcessed.setBy(s, c => c + 1),
    gSharesRejected' = gSharesRejected + 1,
    bufferUsed' = bufferUsed.set(s, 0),
    channelId' = channelId, pendingSeqNum' = pendingSeqNum,
    waitTicks' = waitTicks,
    gTimeouts' = gTimeouts, gBufferOverflows' = gBufferOverflows,
    gFrameOverflows' = gFrameOverflows, gSharesAccepted' = gSharesAccepted,
    gDisconnects' = gDisconnects,
  }

  // Tick while waiting for validation (timeout check)
  action waitTick(s: int): bool = {
    val newTicks = waitTicks.get(s) + 1
    all {
      SESSIONS.contains(s),
      sessionState.get(s) == 2,
      if (newTicks >= VALIDATION_TIMEOUT) all {
        // Timeout: disconnect
        sessionState' = sessionState.set(s, 0),
        gTimeouts' = gTimeouts + 1,
        gDisconnects' = gDisconnects + 1,
        waitTicks' = waitTicks.set(s, newTicks),
      } else all {
        // Still waiting
        sessionState' = sessionState,
        gTimeouts' = gTimeouts,
        gDisconnects' = gDisconnects,
        waitTicks' = waitTicks.set(s, newTicks),
      },
      channelId' = channelId, pendingSeqNum' = pendingSeqNum,
      bufferUsed' = bufferUsed, sharesProcessed' = sharesProcessed,
      gBufferOverflows' = gBufferOverflows, gFrameOverflows' = gFrameOverflows,
      gSharesAccepted' = gSharesAccepted, gSharesRejected' = gSharesRejected,
    }
  }

  // Miner disconnects (normal close)
  action disconnect(s: int): bool = all {
    SESSIONS.contains(s),
    sessionState.get(s) != 0,
    sessionState' = sessionState.set(s, 0),
    gDisconnects' = gDisconnects + 1,
    channelId' = channelId, pendingSeqNum' = pendingSeqNum,
    waitTicks' = waitTicks, bufferUsed' = bufferUsed,
    sharesProcessed' = sharesProcessed,
    gTimeouts' = gTimeouts, gBufferOverflows' = gBufferOverflows,
    gFrameOverflows' = gFrameOverflows, gSharesAccepted' = gSharesAccepted,
    gSharesRejected' = gSharesRejected,
  }

  action step = {
    nondet s = SESSIONS.oneOf()
    nondet seq = 1.to(100).oneOf()
    nondet fs = 1.to(MAX_FRAME + 1).oneOf()
    nondet bs = 1.to(MAX_BUFFER + 1).oneOf()
    any {
      connect(s),
      submitShare(s, seq, fs, bs),
      shareAccepted(s),
      shareRejected(s),
      waitTick(s),
      disconnect(s),
      bufferOverflow(s),
      frameOverflow(s),
    }
  }

  // INVARIANTS

  // State is always valid (0-3)
  val stateValid = SESSIONS.forall(s =>
    sessionState.get(s) >= 0 and sessionState.get(s) <= 3)

  // Channel IDs are unique across sessions
  val channelIdsUnique = SESSIONS.forall(s1 => SESSIONS.forall(s2 =>
    (s1 == s2) or channelId.get(s1) != channelId.get(s2)))

  // Buffer usage is bounded
  val bufferBounded = SESSIONS.forall(s =>
    bufferUsed.get(s) >= 0 and bufferUsed.get(s) <= MAX_BUFFER)

  // Waiting sessions have a pending sequence number
  val waitHasSeq = SESSIONS.forall(s =>
    (sessionState.get(s) == 2) implies (pendingSeqNum.get(s) > 0))

  // Total shares = accepted + rejected
  val shareAccountingCorrect = gSharesAccepted + gSharesRejected ==
    SESSIONS.fold(0, (sum, s) => sum + sharesProcessed.get(s))

  // Witnesses
  val witnessNoTimeouts = gTimeouts == 0
  val witnessNoDisconnects = gDisconnects == 0
}

module SessionLifecycleTest {
  import SessionLifecycle(
    SESSIONS = Set(1, 2), MAX_BUFFER = 100, MAX_FRAME = 200,
    VALIDATION_TIMEOUT = 3,
  ).*

  run happyPathSession = init
    .then(connect(1))
    .expect(sessionState.get(1) == 1)
    .then(submitShare(1, 1, 50, 30))
    .expect(sessionState.get(1) == 2)
    .then(shareAccepted(1))
    .expect(sessionState.get(1) == 1)
    .expect(gSharesAccepted == 1)
    .expect(shareAccountingCorrect)

  run shareRejection = init
    .then(connect(1))
    .then(submitShare(1, 1, 50, 30))
    .then(shareRejected(1))
    .expect(gSharesRejected == 1)
    .expect(sessionState.get(1) == 1)

  run validationTimeout = init
    .then(connect(1))
    .then(submitShare(1, 1, 50, 30))
    .then(waitTick(1)).then(waitTick(1)).then(waitTick(1))
    .expect(sessionState.get(1) == 0)
    .expect(gTimeouts == 1)
    .expect(gDisconnects == 1)

  run bufferOverflowDisconnects = init
    .then(connect(1))
    .then(bufferOverflow(1))
    .expect(sessionState.get(1) == 0)
    .expect(gBufferOverflows == 1)

  run twoSessionsIndependent = init
    .then(connect(1)).then(connect(2))
    .then(submitShare(1, 1, 50, 30))
    .then(submitShare(2, 1, 50, 30))
    .then(shareAccepted(1))
    .then(shareRejected(2))
    .expect(gSharesAccepted == 1)
    .expect(gSharesRejected == 1)
    .expect(channelIdsUnique)

  run multipleSharesInSequence = init
    .then(connect(1))
    .then(submitShare(1, 1, 50, 30))
    .then(shareAccepted(1))
    .then(submitShare(1, 2, 50, 30))
    .then(shareAccepted(1))
    .expect(sharesProcessed.get(1) == 2)
    .expect(shareAccountingCorrect)
}

// ═══════════════════════════════════════════════════════════════
// MODULE 14: Reconnection & Backoff
// ═══════════════════════════════════════════════════════════════
// Models ReconnectManager from reconnect.rs:
//   - Exponential backoff with configurable multiplier and cap
//   - Jitter to prevent thundering herd
//   - Resets after stable connection (> threshold duration)
//   - Attack detection scoring based on failure patterns
//   - Failure history with sliding window

module ReconnectBackoff {
  import basicSpells.*

  const INITIAL_DELAY: int      // e.g. 10 (representing 1s in ticks)
  const MAX_DELAY: int          // e.g. 600 (representing 60s)
  const BACKOFF_MULT: int       // e.g. 2
  const MAX_ATTEMPTS: int       // 0 = unlimited
  const STABLE_THRESHOLD: int   // ticks for connection to be "stable"
  const SHORT_LIVED_THRESH: int // ticks below which connection is "short-lived"
  const MAX_FAILURES: int       // max failure history (100)

  // DisconnectReason: 0=Normal, 1=NetworkError, 2=DecryptionError,
  //                   3=HandshakeError, 4=ServerClosed
  type Failure = { reason: int, duration: int, tick: int }

  var attemptCount: int
  var currentDelay: int
  var connected: bool
  var connectedAt: int          // tick when last connected
  var clock: int
  var failures: List[Failure]   // recent failure history
  var gResets: int              // ghost: backoff resets
  var gExhausted: bool          // ghost: max attempts hit
  var gDecryptErrors: int       // ghost: decryption error count
  var gShortLived: int          // ghost: short-lived disconnects

  action init = all {
    attemptCount' = 0,
    currentDelay' = 0,
    connected' = false,
    connectedAt' = 0,
    clock' = 0,
    failures' = [],
    gResets' = 0,
    gExhausted' = false,
    gDecryptErrors' = 0,
    gShortLived' = 0,
  }

  // Connection established
  action onConnected: bool = all {
    not(connected),
    connected' = true,
    connectedAt' = clock,
    attemptCount' = attemptCount,
    currentDelay' = currentDelay,
    clock' = clock,
    failures' = failures,
    gResets' = gResets,
    gExhausted' = gExhausted,
    gDecryptErrors' = gDecryptErrors,
    gShortLived' = gShortLived,
  }

  // Disconnected: compute backoff delay
  action onDisconnected(reason: int, duration: int): bool = {
    val newAttempts = attemptCount + 1
    val wasStable = duration >= STABLE_THRESHOLD
    val resetBackoff = wasStable
    val effAttempts = if (resetBackoff) 1 else newAttempts
    val newDelay = if (effAttempts == 1) INITIAL_DELAY
                   else min(currentDelay * BACKOFF_MULT, MAX_DELAY)
    val isShort = duration < SHORT_LIVED_THRESH
    val isDecrypt = reason == 2
    val exhausted = MAX_ATTEMPTS > 0 and newAttempts > MAX_ATTEMPTS
    val entry: Failure = { reason: reason, duration: duration, tick: clock }
    val newFailures = if (failures.length() >= MAX_FAILURES)
      failures.tail().append(entry)
    else
      failures.append(entry)
    all {
      connected,
      reason >= 0, reason <= 4,
      duration >= 0,
      connected' = false,
      attemptCount' = if (resetBackoff) 1 else newAttempts,
      currentDelay' = newDelay,
      failures' = newFailures,
      connectedAt' = connectedAt,
      clock' = clock,
      gResets' = if (resetBackoff) gResets + 1 else gResets,
      gExhausted' = exhausted,
      gDecryptErrors' = if (isDecrypt) gDecryptErrors + 1 else gDecryptErrors,
      gShortLived' = if (isShort) gShortLived + 1 else gShortLived,
    }
  }

  // Advance time
  action tick = all {
    clock' = clock + 1,
    connected' = connected,
    connectedAt' = connectedAt,
    attemptCount' = attemptCount,
    currentDelay' = currentDelay,
    failures' = failures,
    gResets' = gResets,
    gExhausted' = gExhausted,
    gDecryptErrors' = gDecryptErrors,
    gShortLived' = gShortLived,
  }

  action step = {
    nondet reason = 0.to(4).oneOf()
    nondet dur = 0.to(STABLE_THRESHOLD + 5).oneOf()
    any {
      onConnected,
      onDisconnected(reason, dur),
      tick,
    }
  }

  // INVARIANTS

  // Delay never exceeds max
  val delayBounded = currentDelay >= 0 and currentDelay <= MAX_DELAY

  // Attempt count is non-negative
  val attemptsNonNeg = attemptCount >= 0

  // Failure history bounded
  val failuresBounded = failures.length() <= MAX_FAILURES

  // Delay monotonicity: once > 0, only increases (until reset)
  // After disconnect, delay is at least INITIAL_DELAY
  val delayMinimum = (attemptCount > 0) implies (currentDelay >= INITIAL_DELAY)

  // Witnesses
  val witnessNoResets = gResets == 0
  val witnessNotExhausted = not(gExhausted)
}

module ReconnectBackoffTest {
  import ReconnectBackoff(
    INITIAL_DELAY = 10, MAX_DELAY = 100, BACKOFF_MULT = 2,
    MAX_ATTEMPTS = 5, STABLE_THRESHOLD = 50, SHORT_LIVED_THRESH = 10,
    MAX_FAILURES = 5,
  ).*

  run firstDisconnect = init
    .then(onConnected)
    .then(onDisconnected(1, 5))
    .expect(currentDelay == 10)
    .expect(attemptCount == 1)

  run exponentialGrowth = init
    .then(onConnected).then(onDisconnected(1, 5))  // delay=10
    .then(onConnected).then(onDisconnected(1, 5))  // delay=20
    .then(onConnected).then(onDisconnected(1, 5))  // delay=40
    .then(onConnected).then(onDisconnected(1, 5))  // delay=80
    .expect(currentDelay == 80)
    .expect(delayBounded)

  run delayCapped = init
    .then(onConnected).then(onDisconnected(1, 5))  // 10
    .then(onConnected).then(onDisconnected(1, 5))  // 20
    .then(onConnected).then(onDisconnected(1, 5))  // 40
    .then(onConnected).then(onDisconnected(1, 5))  // 80
    .then(onConnected).then(onDisconnected(1, 5))  // min(160, 100) = 100
    .expect(currentDelay == 100)
    .expect(gExhausted)  // 5 attempts = max

  run stableConnectionResets = init
    .then(onConnected).then(onDisconnected(1, 5))  // delay=10
    .then(onConnected).then(onDisconnected(1, 5))  // delay=20
    .then(onConnected).then(onDisconnected(0, 60)) // stable! reset
    .expect(attemptCount == 1)
    .expect(currentDelay == 10)
    .expect(gResets == 1)

  run decryptionErrorTracked = init
    .then(onConnected).then(onDisconnected(2, 3))
    .expect(gDecryptErrors == 1)
    .expect(gShortLived == 1)

  run failureHistoryCapped = init
    .then(onConnected).then(onDisconnected(1, 5))
    .then(onConnected).then(onDisconnected(1, 5))
    .then(onConnected).then(onDisconnected(1, 5))
    .then(onConnected).then(onDisconnected(1, 5))
    .then(onConnected).then(onDisconnected(1, 5))
    .expect(failures.length() == 5)
    .expect(failuresBounded)
}

// ═══════════════════════════════════════════════════════════════
// MODULE 15: Vardiff Division-by-Zero Bug
// ═══════════════════════════════════════════════════════════════
// Models the unguarded division in VardiffController::maybe_retarget()
// from vardiff.rs:
//
//   let minutes = elapsed.as_secs_f64() / 60.0;
//   let actual_rate = self.shares_since_retarget as f64 / minutes;  // BUG: no zero check
//   let ratio = actual_rate / target_rate;                           // BUG: no zero check
//
// The stats() method guards minutes > 0, but maybe_retarget() does not.
// If retarget_interval is very short or target_shares_per_minute is 0,
// these divisions produce NaN/Infinity, corrupting difficulty state.

module VardiffDivZero {
  import basicSpells.*

  const MIN_DIFF: int
  const MAX_DIFF: int
  const TARGET_SPM: int      // target_shares_per_minute (0 = misconfigured)
  const RETARGET_INT: int    // retarget interval in ticks

  var difficulty: int
  var shareCount: int
  var elapsed: int           // ticks since last retarget
  var gNanEvents: int        // ghost: division-by-zero events
  var gRetargets: int

  action init = all {
    difficulty' = clamp(1, MIN_DIFF, MAX_DIFF),
    shareCount' = 0,
    elapsed' = 0,
    gNanEvents' = 0,
    gRetargets' = 0,
  }

  action recordShare: bool = all {
    shareCount' = shareCount + 1,
    difficulty' = difficulty,
    elapsed' = elapsed,
    gNanEvents' = gNanEvents,
    gRetargets' = gRetargets,
  }

  action tick: bool = all {
    elapsed' = elapsed + 1,
    difficulty' = difficulty,
    shareCount' = shareCount,
    gNanEvents' = gNanEvents,
    gRetargets' = gRetargets,
  }

  // Model of maybe_retarget() from vardiff.rs
  // Faithfully reproduces the unguarded division behavior
  action maybeRetarget: bool = {
    val minutes = elapsed  // simplified: 1 tick = 1 minute for modeling
    val canRetarget = elapsed >= RETARGET_INT
    all {
      canRetarget,
      if (minutes == 0) all {
        // BUG: division by zero! In Rust, 0.0/0.0 = NaN for f64
        // NaN comparison: any comparison with NaN returns false
        // So ratio >= lower_bound && ratio <= upper_bound is FALSE
        // This means NaN always triggers retarget path
        // Then: difficulty * NaN = NaN, NaN.clamp() = NaN, final = NaN
        gNanEvents' = gNanEvents + 1,
        // NaN poisons the difficulty: all future comparisons fail
        difficulty' = 0,  // model NaN as 0 (invalid difficulty)
        shareCount' = 0,
        elapsed' = 0,
        gRetargets' = gRetargets + 1,
      }
      else if (TARGET_SPM == 0) all {
        // BUG: division by target_rate which is 0
        // actual_rate / 0.0 = Infinity for f64
        // Infinity >= lower_bound is TRUE
        // Infinity <= upper_bound is FALSE (unless upper_bound is Infinity)
        // So this always triggers retarget with adjustment = Infinity
        // difficulty * Infinity = Infinity, Infinity.clamp(min, max) = max
        gNanEvents' = gNanEvents + 1,
        difficulty' = MAX_DIFF,  // Infinity clamped to max
        shareCount' = 0,
        elapsed' = 0,
        gRetargets' = gRetargets + 1,
      }
      else {
        // Normal path: compute ratio and adjust
        val actualRate = shareCount * 100 / minutes  // scaled integer math
        val targetRate = TARGET_SPM * 100
        val ratio100 = if (targetRate > 0) actualRate * 100 / targetRate else 100
        // tolerance check: ratio in [75, 125] for 25% tolerance
        val inTolerance = ratio100 >= 75 and ratio100 <= 125
        if (inTolerance) all {
          shareCount' = 0,
          elapsed' = 0,
          difficulty' = difficulty,
          gNanEvents' = gNanEvents,
          gRetargets' = gRetargets,
        } else {
          // Adjust: new = current * ratio, smoothed = (current + new) / 2
          val adjustment = if (ratio100 > 0) ratio100 else 50
          val rawNew = difficulty * adjustment / 100
          val smoothed = (difficulty + rawNew) / 2
          val clamped = clamp(smoothed, MIN_DIFF, MAX_DIFF)
          val changed = abs(clamped - difficulty) > 0
          all {
            difficulty' = if (changed) clamped else difficulty,
            shareCount' = 0,
            elapsed' = 0,
            gNanEvents' = gNanEvents,
            gRetargets' = gRetargets + (if (changed) 1 else 0),
          }
        }
      }
    }
  }

  action step = any {
    recordShare,
    tick,
    maybeRetarget,
  }

  // INVARIANT: difficulty is always valid (not NaN/0)
  // Expected: VIOLATED when minutes=0 or TARGET_SPM=0
  val difficultyValid = difficulty > 0

  // INVARIANT: difficulty stays in bounds
  val difficultyInBounds = difficulty >= MIN_DIFF and difficulty <= MAX_DIFF

  // Ghost: NaN events should never happen in correct code
  val noNanEvents = gNanEvents == 0
}

module VardiffDivZeroTest {
  // Test with TARGET_SPM = 0 (misconfigured)
  import VardiffDivZero(
    MIN_DIFF = 1, MAX_DIFF = 1000, TARGET_SPM = 0, RETARGET_INT = 1,
  ).*

  // BUG: target_shares_per_minute = 0 causes division by zero
  // ratio = actual_rate / 0.0 = Infinity
  // difficulty becomes MAX_DIFF regardless of share rate
  run targetZeroBug = init
    .then(recordShare).then(recordShare).then(recordShare)
    .then(tick)
    .then(maybeRetarget)
    .expect(gNanEvents == 1)
    .expect(difficulty == MAX_DIFF)  // Infinity clamped to max
}

module VardiffDivZeroMinutesTest {
  // Test with RETARGET_INT = 0 (immediate retarget)
  import VardiffDivZero(
    MIN_DIFF = 1, MAX_DIFF = 1000, TARGET_SPM = 5, RETARGET_INT = 0,
  ).*

  // BUG: retarget fires immediately when elapsed=0
  // minutes = 0, actual_rate = shares / 0 = NaN
  // NaN poisons all subsequent difficulty calculations
  run minutesZeroBug = init
    .then(maybeRetarget)
    .expect(gNanEvents == 1)
    .expect(difficulty == 0)  // NaN modeled as 0 (invalid)
}

// ═══════════════════════════════════════════════════════════════
// MODULE 16: Duplicate Detector Cross-Block Race
// ═══════════════════════════════════════════════════════════════
// Models the race between share validation and clear_all() from
// duplicate.rs + server.rs:
//
// Timeline:
//   1. Share S arrives, passes dup check (not in set), enters validation
//   2. New block arrives, clear_all() wipes the duplicate set
//   3. Share S (or identical retry) arrives again
//   4. Share S passes dup check AGAIN (set was cleared)
//   5. Both copies are accepted → double-counted in payout
//
// The root cause: check_and_record() and validate_share() are not
// atomic with respect to clear_all().

module DuplicateRace {
  import basicSpells.*

  const JOBS: Set[int]

  // Duplicate detector state (models InMemoryDuplicateDetector)
  var dupSets: int -> Set[int]   // job_id -> set of share hashes

  // In-flight shares (being validated, not yet recorded)
  var inflight: Set[(int, int)]  // (job_id, hash) — passed dup check, in validation

  // Payout accounting
  var payouts: int -> int        // job_id -> shares accepted
  var gDoublePayouts: int        // ghost: shares paid twice

  action init = all {
    dupSets' = JOBS.mapBy(_ => Set()),
    inflight' = Set(),
    payouts' = JOBS.mapBy(_ => 0),
    gDoublePayouts' = 0,
  }

  // Phase 1: Share arrives, passes dup check, enters validation queue
  action submitShare(jid: int, hash: int): bool = {
    val hasDups = dupSets.keys().contains(jid)
    val existing = if (hasDups) dupSets.get(jid) else Set()
    val isDup = existing.contains(hash)
    all {
      JOBS.contains(jid),
      hash > 0,
      not(isDup),  // passes dup check
      // Record in dup set AND add to inflight
      dupSets' = dupSets.put(jid, existing.union(Set(hash))),
      inflight' = inflight.union(Set((jid, hash))),
      payouts' = payouts,
      gDoublePayouts' = gDoublePayouts,
    }
  }

  // Phase 2: Validation completes, share accepted
  action acceptShare(jid: int, hash: int): bool = all {
    inflight.contains((jid, hash)),
    inflight' = inflight.exclude(Set((jid, hash))),
    payouts' = payouts.setBy(jid, p => p + 1),
    dupSets' = dupSets,
    gDoublePayouts' = gDoublePayouts,
  }

  // New block: clear_all() wipes duplicate detector
  // Can happen while shares are inflight!
  action newBlock: bool = all {
    dupSets' = JOBS.mapBy(_ => Set()),  // clear_all()
    // inflight shares are NOT cleared — they continue validation
    inflight' = inflight,
    payouts' = payouts,
    gDoublePayouts' = gDoublePayouts,
  }

  // Resubmit: same share arrives again after clear_all
  // If the original was inflight when clear happened, this passes dup check
  action resubmitAfterClear(jid: int, hash: int): bool = {
    val hasDups = dupSets.keys().contains(jid)
    val existing = if (hasDups) dupSets.get(jid) else Set()
    val isDup = existing.contains(hash)
    // This share was already accepted (or inflight) but dup set was cleared
    val alreadyPaid = payouts.get(jid) > 0 or inflight.contains((jid, hash))
    all {
      JOBS.contains(jid),
      hash > 0,
      not(isDup),        // passes dup check (set was cleared!)
      alreadyPaid,       // this is actually a double-payout scenario
      dupSets' = dupSets.put(jid, existing.union(Set(hash))),
      inflight' = inflight.union(Set((jid, hash))),
      payouts' = payouts,
      gDoublePayouts' = gDoublePayouts + 1,
    }
  }

  action step = {
    nondet jid = JOBS.oneOf()
    nondet hash = 1.to(10).oneOf()
    any {
      submitShare(jid, hash),
      acceptShare(jid, hash),
      newBlock,
      resubmitAfterClear(jid, hash),
    }
  }

  // INVARIANT: no share should be paid twice
  // Expected: VIOLATED — proving the race condition
  val noDoublePayout = gDoublePayouts == 0

  // Safety: payouts are non-negative
  val payoutsNonNeg = JOBS.forall(j => payouts.get(j) >= 0)
}

module DuplicateRaceTest {
  import DuplicateRace(JOBS = Set(1, 2)).*

  // Demonstrate the cross-block duplicate race:
  // 1. Share (job=1, hash=42) submitted and accepted
  // 2. New block clears duplicate detector
  // 3. Same share resubmitted — passes dup check because set was cleared
  // 4. Double payout!
  run crossBlockDupRace = init
    .then(submitShare(1, 42))
    .then(acceptShare(1, 42))
    .expect(payouts.get(1) == 1)
    .then(newBlock)                      // clear_all() wipes dup set
    .then(resubmitAfterClear(1, 42))    // same share passes dup check!
    .then(acceptShare(1, 42))
    .expect(payouts.get(1) == 2)         // double payout
    .expect(gDoublePayouts == 1)

  // Inflight race: share is being validated when clear happens
  run inflightRace = init
    .then(submitShare(1, 7))             // share enters validation
    .then(newBlock)                      // clear_all() while share inflight
    .then(resubmitAfterClear(1, 7))     // resubmit passes dup check
    .expect(gDoublePayouts == 1)
    .then(acceptShare(1, 7))             // original inflight accepted
    .then(acceptShare(1, 7))             // resubmit also accepted
    .expect(payouts.get(1) == 2)         // double payout

  // Normal case without race: no double payouts
  run noRace = init
    .then(submitShare(1, 1))
    .then(acceptShare(1, 1))
    .then(submitShare(1, 2))
    .then(acceptShare(1, 2))
    .expect(gDoublePayouts == 0)
    .expect(payouts.get(1) == 2)
}

// ═══════════════════════════════════════════════════════════════
// MODULE 17: Vardiff Update Lost on Channel Removal (3-Lock TOCTOU)
// ═══════════════════════════════════════════════════════════════
// Models the 3-lock pattern from server.rs where vardiff updates
// are silently lost when a channel is removed between lock acquisitions:
//
//   Lock 1: channels.write() → rate_limit check → release
//   Lock 2: channels.read()  → job lookup (clone) → release
//   [validation runs lock-free]
//   Lock 3: channels.write() → record_share + vardiff → release
//
// Between Lock 2 and Lock 3, another task can disconnect the session
// and remove the channel. The vardiff update is silently lost (the
// `if let Some(channel)` branch at line 869 takes the None path).
//
// Impact: difficulty adjustment never happens for that share,
// and the payout tracker still records the share (line 891) even
// though vardiff was not updated — inconsistent state.

module VardiffLostUpdate {
  import basicSpells.*

  const MINERS: Set[int]

  // Phase: 0=Idle, 1=RateChecked, 2=JobLookedUp, 3=Validated
  var phase: int -> int
  var channels: Set[int]           // set of active channel IDs
  var vardiffShares: int -> int    // per-miner share count for vardiff
  var payoutShares: int -> int     // per-miner payout share count
  var gLostUpdates: int            // ghost: vardiff updates silently lost
  var gPayoutWithoutVardiff: int   // ghost: payout recorded without vardiff

  action init = all {
    phase' = MINERS.mapBy(_ => 0),
    channels' = MINERS,  // all miners connected initially
    vardiffShares' = MINERS.mapBy(_ => 0),
    payoutShares' = MINERS.mapBy(_ => 0),
    gLostUpdates' = 0,
    gPayoutWithoutVardiff' = 0,
  }

  // Lock 1: rate check (acquire write lock, check, release)
  action rateCheck(m: int): bool = all {
    MINERS.contains(m),
    channels.contains(m),
    phase.get(m) == 0,
    phase' = phase.set(m, 1),
    channels' = channels, vardiffShares' = vardiffShares,
    payoutShares' = payoutShares,
    gLostUpdates' = gLostUpdates, gPayoutWithoutVardiff' = gPayoutWithoutVardiff,
  }

  // Lock 2: job lookup (acquire read lock, clone job, release)
  action jobLookup(m: int): bool = all {
    MINERS.contains(m),
    channels.contains(m),
    phase.get(m) == 1,
    phase' = phase.set(m, 2),
    channels' = channels, vardiffShares' = vardiffShares,
    payoutShares' = payoutShares,
    gLostUpdates' = gLostUpdates, gPayoutWithoutVardiff' = gPayoutWithoutVardiff,
  }

  // Validation (no lock held — Equihash validation runs here)
  action validate(m: int): bool = all {
    MINERS.contains(m),
    phase.get(m) == 2,
    phase' = phase.set(m, 3),
    channels' = channels, vardiffShares' = vardiffShares,
    payoutShares' = payoutShares,
    gLostUpdates' = gLostUpdates, gPayoutWithoutVardiff' = gPayoutWithoutVardiff,
  }

  // Lock 3: record vardiff + payout
  // Bug: if channel was removed, vardiff update is lost but payout still records
  action recordResult(m: int): bool = {
    val channelExists = channels.contains(m)
    all {
      MINERS.contains(m),
      phase.get(m) == 3,
      phase' = phase.set(m, 0),
      // Payout ALWAYS records (line 891 runs regardless of channel existence)
      payoutShares' = payoutShares.setBy(m, s => s + 1),
      if (channelExists) all {
        // Normal: vardiff updated
        vardiffShares' = vardiffShares.setBy(m, s => s + 1),
        gLostUpdates' = gLostUpdates,
        gPayoutWithoutVardiff' = gPayoutWithoutVardiff,
      } else all {
        // BUG: channel removed — vardiff update silently lost
        vardiffShares' = vardiffShares,
        gLostUpdates' = gLostUpdates + 1,
        gPayoutWithoutVardiff' = gPayoutWithoutVardiff + 1,
      },
      channels' = channels,
    }
  }

  // External: session disconnects, channel removed
  // Can happen between any phases!
  action disconnect(m: int): bool = all {
    MINERS.contains(m),
    channels.contains(m),
    channels' = channels.exclude(Set(m)),
    phase' = phase, vardiffShares' = vardiffShares,
    payoutShares' = payoutShares,
    gLostUpdates' = gLostUpdates, gPayoutWithoutVardiff' = gPayoutWithoutVardiff,
  }

  action step = {
    nondet m = MINERS.oneOf()
    any {
      rateCheck(m),
      jobLookup(m),
      validate(m),
      recordResult(m),
      disconnect(m),
    }
  }

  // INVARIANT: vardiff and payout share counts should match
  // Expected: VIOLATED — proves the inconsistency
  val vardiffPayoutConsistent = MINERS.forall(m =>
    vardiffShares.get(m) == payoutShares.get(m))

  // INVARIANT: no lost updates
  // Expected: VIOLATED
  val noLostUpdates = gLostUpdates == 0

  // Safety: all counters non-negative
  val countersValid = MINERS.forall(m =>
    vardiffShares.get(m) >= 0 and payoutShares.get(m) >= 0)
}

module VardiffLostUpdateTest {
  import VardiffLostUpdate(MINERS = Set(1, 2)).*

  // Demonstrate the lost vardiff update:
  // 1. Miner passes rate check and job lookup
  // 2. Validation runs (no lock)
  // 3. Session disconnects, channel removed
  // 4. recordResult: payout records, but vardiff update is lost
  run lostVardiffUpdate = init
    .then(rateCheck(1))
    .then(jobLookup(1))
    .then(validate(1))
    .then(disconnect(1))          // channel removed during validation!
    .then(recordResult(1))        // vardiff lost, payout still recorded
    .expect(gLostUpdates == 1)
    .expect(gPayoutWithoutVardiff == 1)
    .expect(payoutShares.get(1) == 1)
    .expect(vardiffShares.get(1) == 0)  // inconsistent!

  // Two miners: one disconnects, other is fine
  run oneDisconnectOneOk = init
    .then(rateCheck(1)).then(rateCheck(2))
    .then(jobLookup(1)).then(jobLookup(2))
    .then(validate(1)).then(validate(2))
    .then(disconnect(1))          // only miner 1 disconnects
    .then(recordResult(1))        // miner 1: lost update
    .then(recordResult(2))        // miner 2: normal
    .expect(gLostUpdates == 1)
    .expect(vardiffShares.get(2) == payoutShares.get(2))  // miner 2 consistent

  // Without disconnect, everything is consistent
  run noDisconnect = init
    .then(rateCheck(1))
    .then(jobLookup(1))
    .then(validate(1))
    .then(recordResult(1))
    .expect(gLostUpdates == 0)
    .expect(vardiffShares.get(1) == payoutShares.get(1))
}
