//! Attributing acton-ai's broadcast tool events to the client that caused them.
//!
//! # The problem this actor exists to solve
//!
//! acton-ai broadcasts a turn's whole observable life — [`TurnLifecycle`],
//! [`LLMStreamToolResult`] and [`PlanUpdated`] — to the runtime-wide broker,
//! keyed by an `acton_ai::types::TurnId` that the prompt loop mints
//! internally. A caller of `collect()` is never told that identifier, and no
//! callback carries it. One process serving several clients therefore receives
//! every client's events on one channel with no way to tell them apart.
//!
//! Approvals do not have this problem: they run on the turn's own task, so
//! [`crate::approval`] identifies them exactly with a task-local. Only the
//! broadcast events, which arrive on the broker's task, need a registry.
//!
//! # What this router forwards
//!
//! - tool calls starting and finishing, as ACP tool-call updates;
//! - the model's plan, as a spec-native `sessionUpdate: "plan"` carrying
//!   Garrison's correlation in `_meta.garrison`;
//! - a history summarized to fit the window, as
//!   [`acp::ext::SESSION_COMPACTED`].
//!
//! Each goes to the one session that owns the turn it names and to no other,
//! which is what the table below is for. Successive plans of one turn are
//! forwarded by one actor onto one FIFO sink, so a client sees them in the
//! order the model published them; the final plan also rides in the
//! `session/prompt` response's `_meta`, which is the authoritative end state
//! because the response comes from a different actor and can overtake the last
//! notification.
//!
//! # The claim protocol
//!
//! A thread **claims** before it starts a turn and the router hands out at most
//! one claim at a time. The next `TurnStarted` on the broker therefore belongs
//! to the outstanding claim and nothing else, so the router can bind acton-ai's
//! turn identifier to Garrison's. A second claim waits — parked on its reply
//! envelope, so the asking thread simply has not returned yet — until the first
//! is bound.
//!
//! What gets serialized is the window between claiming and acton-ai publishing
//! `TurnStarted`, which is an admission check and a broadcast: no IO, no model
//! call, microseconds. Turns themselves run fully concurrently.
//!
//! A claim that is never bound — a `collect()` that fails before admission —
//! would hold that window open, so every claim is armed with
//! [`CLAIM_DEADLINE`] and released if nothing binds it.
//!
//! # When this can be deleted
//!
//! All of it collapses into a single `HashMap` insert the day acton-ai either
//! returns the `TurnId` it minted or carries it on the stream events. That is
//! filed as an upstream gap; nothing here changes the protocol if it lands.

use crate::protocol::acp;
use crate::protocol::codec::EventSink;
use crate::protocol::conn::{Describe, StatusPart};
use crate::types::{ThreadId, TurnId};
use acton_ai::messages::{LLMStreamToolResult, PlanUpdated, TurnLifecycle};
use acton_ai::types::{CorrelationId, TurnId as ActonTurnId};
use acton_reactive::prelude::*;
use std::collections::{HashMap, VecDeque};
use std::time::Duration;

/// How long an outstanding claim may go unbound before it is released.
///
/// Enormous next to the microseconds the window actually takes; short enough
/// that a wedged claim cannot stall turn starts for a whole session.
pub const CLAIM_DEADLINE: Duration = Duration::from_secs(10);

/// How many disowned turns are remembered at once.
///
/// A disowned id is normally forgotten the moment its `TurnStarted` arrives,
/// so this bound is only reached by turns that were disowned and then never
/// started — a `collect()` that failed before admission. Holding the newest
/// and dropping the oldest keeps that leak bounded without a second timer:
/// far more completions can be in flight than any editor will ever ask for,
/// and one that is evicted is merely routed as it would have been before.
const DISOWNED_CAPACITY: usize = 64;

/// One thread's stake in the next turn acton-ai starts.
#[derive(Clone, Debug)]
struct Claim {
    thread_id: ThreadId,
    turn_id: TurnId,
    sink: EventSink,
}

/// Asks to be bound to the next turn acton-ai admits.
///
/// Await the reply before calling `collect()`: the reply *is* the exclusion.
#[acton_message]
pub struct ClaimTurn {
    /// The thread about to run a turn.
    pub thread_id: ThreadId,
    /// Garrison's identifier for that turn, which its events will carry.
    pub turn_id: TurnId,
    /// Where to write those events.
    pub sink: EventSink,
}

/// Acknowledges a claim. Holding this means the claimant may start its turn.
#[acton_message]
pub struct TurnClaimed;

impl Request for ClaimTurn {
    type Response = TurnClaimed;
}

/// Discards everything remembered about a turn.
///
/// Sent by the thread when its turn ends, including when it ends by being
/// interrupted — the point at which acton-ai's own `TurnFinished` may never
/// arrive.
#[acton_message]
pub struct ReleaseTurn {
    /// Garrison's identifier for the finished turn.
    pub turn_id: TurnId,
}

/// Acknowledges a release.
#[acton_message]
pub struct TurnReleased;

impl Request for ReleaseTurn {
    type Response = TurnReleased;
}

/// Declares that a turn is not a session's turn and must not be routed.
///
/// Inline completion drives the same prompt loop a turn does, so it publishes
/// the same `TurnStarted` the claim protocol reads. It holds no claim and
/// wants none — it streams nothing and takes microseconds to be worth
/// nothing — but the router cannot tell whose `TurnStarted` it is looking at
/// and would otherwise bind it to whichever claim happened to be outstanding.
///
/// So the caller mints the id itself, disowns it here, and passes it to
/// [`PromptBuilder::turn_id`](acton_ai::prompt::PromptBuilder::turn_id).
/// Await the reply before calling `collect()`: the router has to know the id
/// before the event carrying it can arrive.
#[acton_message]
pub struct DisownTurn {
    /// The acton-ai turn that is about to start and must be ignored.
    pub turn_id: ActonTurnId,
}

/// Acknowledges a disowned turn.
#[acton_message]
pub struct TurnDisowned;

impl Request for DisownTurn {
    type Response = TurnDisowned;
}

/// Fires when an outstanding claim has waited too long to be bound.
///
/// Carries the generation it was armed for, so a timer that loses the race
/// against a real binding is recognized as stale and ignored.
#[acton_message]
struct ClaimExpired {
    generation: u64,
}

/// Owns the mapping from acton-ai's turns to Garrison's clients.
#[acton_actor]
pub struct TurnRouter {
    /// The claim awaiting a `TurnStarted`, if any.
    outstanding: Option<Claim>,
    /// Claims queued behind it, each parked on its caller's reply envelope.
    waiting: VecDeque<(Claim, OutboundEnvelope)>,
    /// Bound turns, by acton-ai's identifier.
    turns: HashMap<ActonTurnId, Claim>,
    /// Which turn a running tool call belongs to.
    calls: HashMap<String, ActonTurnId>,
    /// Which turn a round belongs to, learned from calls that did run.
    correlations: HashMap<CorrelationId, ActonTurnId>,
    /// Bumped on every claim, so a stale expiry can be told from a live one.
    generation: u64,
    /// The armed expiry for [`Self::outstanding`].
    expiry: Option<ScheduledSend>,
    /// Turns that must never be bound to a claim, newest last.
    disowned: VecDeque<ActonTurnId>,
    /// The auto-compaction policy the runtime launched under, for
    /// `_garrison/status`. `None` means histories are truncated rather than
    /// summarized.
    compaction: Option<acp::CompactionStatus>,
    /// How many compactions this daemon has routed since it started.
    compactions: usize,
}

impl TurnRouter {
    /// Spawns the router and subscribes it to the events it routes.
    ///
    /// Subscriptions go on the builder, before `start`: registering them
    /// afterwards is silently ignored and would leave a router that runs
    /// happily and routes nothing.
    ///
    /// `compaction` is the policy acton-ai resolved at launch. It is held here
    /// because this is the actor that watches compaction happen, so one actor
    /// answers both "what is the rule" and "how often has it fired".
    pub async fn spawn(
        runtime: &mut ActorRuntime,
        compaction: Option<acp::CompactionStatus>,
    ) -> ActorHandle {
        let mut builder = runtime.new_actor_with_name::<Self>("turn_router".to_string());

        builder.model.compaction = compaction;
        configure_handlers(&mut builder);

        builder.handle().subscribe::<TurnLifecycle>().await;
        builder.handle().subscribe::<LLMStreamToolResult>().await;
        builder.handle().subscribe::<PlanUpdated>().await;

        builder.start().await
    }

    /// Records a claim as outstanding, or queues it behind the current one.
    ///
    /// Returns the reply to send now, if the claim was admitted immediately.
    fn claim(&mut self, claim: Claim, reply: OutboundEnvelope) -> Option<OutboundEnvelope> {
        if self.outstanding.is_some() {
            self.waiting.push_back((claim, reply));
            return None;
        }
        self.outstanding = Some(claim);
        self.generation = self.generation.wrapping_add(1);
        Some(reply)
    }

    /// Releases the outstanding claim, binding it to `turn_id` when given one.
    ///
    /// Returns the next claimant to acknowledge, if one was queued.
    fn settle(&mut self, turn_id: Option<ActonTurnId>) -> Option<OutboundEnvelope> {
        if let Some(expiry) = self.expiry.take() {
            expiry.cancel();
        }

        match (self.outstanding.take(), turn_id) {
            (Some(claim), Some(turn_id)) => {
                self.turns.insert(turn_id, claim);
            }
            (Some(claim), None) => {
                tracing::debug!(
                    thread_id = %claim.thread_id,
                    turn_id = %claim.turn_id,
                    "claim released without a turn",
                );
            }
            (None, _) => {}
        }

        let (claim, reply) = self.waiting.pop_front()?;
        self.outstanding = Some(claim);
        self.generation = self.generation.wrapping_add(1);
        Some(reply)
    }

    /// Remembers that `turn_id` must not be bound to a claim.
    fn disown(&mut self, turn_id: ActonTurnId) {
        if self.disowned.len() == DISOWNED_CAPACITY {
            self.disowned.pop_front();
        }
        self.disowned.push_back(turn_id);
    }

    /// Whether `turn_id` was disowned, forgetting it if so.
    ///
    /// Consuming the answer is what keeps the set small in the ordinary case:
    /// an id is disowned once, starts once, and is of no further interest.
    fn is_disowned(&mut self, turn_id: &ActonTurnId) -> bool {
        let Some(at) = self
            .disowned
            .iter()
            .position(|disowned| disowned == turn_id)
        else {
            return false;
        };
        self.disowned.remove(at);
        true
    }

    /// Forgets a bound turn and everything indexed against it.
    fn forget(&mut self, turn_id: &ActonTurnId) {
        self.turns.remove(turn_id);
        self.calls.retain(|_, owner| owner != turn_id);
        self.correlations.retain(|_, owner| owner != turn_id);
    }

    /// Forgets a bound turn named by Garrison's identifier.
    ///
    /// A turn that was interrupted before acton-ai bound it may not be in the
    /// table at all, which is not an error: releasing twice is how a caller
    /// guarantees it released once.
    fn forget_garrison(&mut self, turn_id: &TurnId) {
        let Some(acton_turn) = self
            .turns
            .iter()
            .find(|(_, claim)| claim.turn_id == *turn_id)
            .map(|(acton_turn, _)| acton_turn.clone())
        else {
            return;
        };
        self.forget(&acton_turn);
    }

    /// Finds the claim an event that names its own turn belongs to.
    ///
    /// No fallback, deliberately: a plan and a compaction each carry the turn
    /// id acton-ai minted, which the claim protocol bound to a session at
    /// `TurnStarted`. There is never a reason to guess, so an event for a turn
    /// this router does not know is dropped rather than shown to whichever
    /// client happens to be the only one talking.
    fn route_turn(&self, turn_id: &ActonTurnId) -> Option<&Claim> {
        self.turns.get(turn_id)
    }

    /// The plan update one broadcast becomes, and the sink it belongs on.
    ///
    /// Pure, which is what makes owner-only routing testable without a model:
    /// the answer is a notification and an address, and nothing has been
    /// written anywhere yet.
    fn plan_delivery(&self, event: &PlanUpdated) -> Option<(&EventSink, acp::SessionNotification)> {
        let claim = self.route_turn(&event.turn_id)?;
        Some((
            &claim.sink,
            acp::plan_update(
                &claim.thread_id,
                &claim.turn_id,
                &event.tool_call_id,
                &event.plan,
            ),
        ))
    }

    /// The compaction notice one broadcast becomes, and its sink. Pure.
    fn compaction_delivery(
        &self,
        turn_id: &ActonTurnId,
        tokens_before: u64,
        tokens_after: u64,
        messages_elided: u64,
    ) -> Option<(&EventSink, acp::CompactionNotice)> {
        let claim = self.route_turn(turn_id)?;
        Some((
            &claim.sink,
            acp::compaction_notice(
                &claim.thread_id,
                &claim.turn_id,
                tokens_before,
                tokens_after,
                messages_elided,
            ),
        ))
    }

    /// What the router contributes to `_garrison/status`.
    fn context_status(&self) -> acp::ContextStatus {
        acp::ContextStatus {
            compaction: self.compaction.clone(),
            compactions: self.compactions,
        }
    }

    /// Finds the claim a tool result belongs to.
    ///
    /// Three routes, in descending order of certainty:
    ///
    /// 1. The call started, so its identifier is bound.
    /// 2. The call never started — the policy gate refused it — but another
    ///    call in the same round did, which pins the round to a turn.
    /// 3. Exactly one turn is bound, so there is nowhere else it could belong.
    ///
    /// Returning `None` means a refused call in a round that ran nothing else,
    /// while another client had a turn open. The event is dropped rather than
    /// shown to the wrong client.
    fn route_result(&self, tool_call_id: &str, correlation_id: &CorrelationId) -> Option<&Claim> {
        if let Some(turn_id) = self.calls.get(tool_call_id) {
            return self.turns.get(turn_id);
        }
        if let Some(turn_id) = self.correlations.get(correlation_id) {
            return self.turns.get(turn_id);
        }
        if self.turns.len() == 1 {
            return self.turns.values().next();
        }
        None
    }
}

/// Wires the router's handlers.
///
/// Every one of them mutates the tables, so every one is `mutate_on`: the
/// message loop is the mutual exclusion that keeps the claim protocol a
/// protocol rather than a race.
fn configure_handlers(builder: &mut ManagedActor<Idle, TurnRouter>) {
    builder.mutate_on::<ClaimTurn>(|actor, envelope| {
        let message = envelope.message();
        let claim = Claim {
            thread_id: message.thread_id.clone(),
            turn_id: message.turn_id.clone(),
            sink: message.sink.clone(),
        };

        let admitted = actor.model.claim(claim, envelope.reply_envelope());
        if admitted.is_some() {
            let expiry = actor.handle().send_after(
                ClaimExpired {
                    generation: actor.model.generation,
                },
                CLAIM_DEADLINE,
            );
            actor.model.expiry = Some(expiry);
        }

        Reply::pending(async move {
            if let Some(reply) = admitted {
                reply.send(TurnClaimed).await;
            }
        })
    });

    builder.mutate_on::<ReleaseTurn>(|actor, envelope| {
        actor.model.forget_garrison(&envelope.message().turn_id);
        let reply = envelope.reply_envelope();
        Reply::pending(async move {
            reply.send(TurnReleased).await;
        })
    });

    builder.mutate_on::<DisownTurn>(|actor, envelope| {
        actor.model.disown(envelope.message().turn_id.clone());
        let reply = envelope.reply_envelope();
        Reply::pending(async move {
            reply.send(TurnDisowned).await;
        })
    });

    builder.mutate_on::<ClaimExpired>(|actor, envelope| {
        if envelope.message().generation != actor.model.generation {
            return Reply::ready();
        }
        tracing::warn!(
            generation = actor.model.generation,
            "a turn claim went unbound; releasing it",
        );
        let next = actor.model.settle(None);
        arm_expiry(actor, next.is_some());
        Reply::pending(async move {
            if let Some(reply) = next {
                reply.send(TurnClaimed).await;
            }
        })
    });

    builder.mutate_on::<TurnLifecycle>(|actor, envelope| {
        let event = envelope.message().clone();
        let mut next = None;

        match &event {
            TurnLifecycle::TurnStarted { turn_id, .. } => {
                // A disowned turn is not anybody's: settling on it would hand
                // the outstanding claim to a completion, and the turn that
                // actually holds that claim would then route nowhere.
                if actor.model.is_disowned(turn_id) {
                    return Reply::ready();
                }

                // No announcement: ACP has no "turn started" event, and the
                // client already knows — it is the one holding the open
                // `session/prompt` request this turn answers.
                next = actor.model.settle(Some(turn_id.clone()));
                arm_expiry(actor, next.is_some());
            }
            // The refused turn's id is not read here on purpose. A turn
            // acton-ai never admitted holds no claim to release, so there is
            // nothing to settle *on*; settling on `None` simply lets the next
            // waiter through. The id matters to the trail, which seals it,
            // not to the router.
            TurnLifecycle::TurnRefused { .. } => {
                next = actor.model.settle(None);
                arm_expiry(actor, next.is_some());
            }
            TurnLifecycle::TurnFinished { turn_id, .. } => actor.model.forget(turn_id),
            TurnLifecycle::ToolStarted {
                turn_id,
                tool_call_id,
                tool_name,
                ..
            } => {
                actor
                    .model
                    .calls
                    .insert(tool_call_id.clone(), turn_id.clone());
                if let Some(claim) = actor.model.turns.get(turn_id) {
                    claim.sink.notify(
                        acp::method::SESSION_UPDATE,
                        // No arguments: acton-ai's `ToolStarted` does not
                        // carry them, so the client learns the input from the
                        // permission request or not at all. Listed upstream.
                        &acp::tool_call_started(&claim.thread_id, tool_call_id, tool_name, None),
                    );
                }
            }
            // The outcome travels on `LLMStreamToolResult`, which carries the
            // success flag and summary this variant lacks.
            TurnLifecycle::ToolFinished { .. } => {}
            TurnLifecycle::ContextCompacted {
                turn_id,
                tokens_before,
                tokens_after,
                messages_elided,
            } => {
                // Counted whether or not it can be attributed: the figure in
                // `_garrison/status` is the daemon's, not one session's.
                actor.model.compactions = actor.model.compactions.saturating_add(1);
                if let Some((sink, notice)) = actor.model.compaction_delivery(
                    turn_id,
                    *tokens_before,
                    *tokens_after,
                    *messages_elided,
                ) {
                    sink.notify(acp::ext::SESSION_COMPACTED, &notice);
                }
            }
            // The enum is non_exhaustive: variants this router has no ACP
            // mapping for yet are deliberately not surfaced rather than being
            // a compile error on every upgrade.
            _ => {}
        }

        Reply::pending(async move {
            if let Some(reply) = next {
                reply.send(TurnClaimed).await;
            }
        })
    });

    // `mutate_on` for the same reason the others are: one FIFO mailbox is
    // what makes successive plans of one turn reach the client in the order
    // the model published them.
    builder.mutate_on::<PlanUpdated>(|actor, envelope| {
        let event = envelope.message();

        match actor.model.plan_delivery(event) {
            Some((sink, update)) => {
                sink.notify(acp::method::SESSION_UPDATE, &update);
            }
            None => tracing::debug!(
                turn_id = %event.turn_id,
                "dropping a plan that belongs to no known turn",
            ),
        }

        Reply::ready()
    });

    // The router's contribution to `_garrison/status`: what this daemon does
    // when a history outgrows the window, and how often it has had to.
    builder.mutate_on::<Describe>(|actor, envelope| {
        let reply = envelope.reply_envelope();
        let part = StatusPart::Context(actor.model.context_status());
        Reply::pending(async move {
            reply.send(part).await;
        })
    });

    builder.mutate_on::<LLMStreamToolResult>(|actor, envelope| {
        let result = envelope.message();

        // A call the router never saw start is a call the *client* never saw
        // start either — the policy gate refused it before the prompt loop
        // announced it. ACP updates an object that must already exist, so the
        // refusal has to introduce the call before closing it, or the client
        // is updating something it has never heard of.
        let announced = actor.model.calls.contains_key(&result.tool_call_id);

        match actor
            .model
            .route_result(&result.tool_call_id, &result.correlation_id)
        {
            Some(claim) => {
                if !announced {
                    claim.sink.notify(
                        acp::method::SESSION_UPDATE,
                        &acp::tool_call_started(
                            &claim.thread_id,
                            &result.tool_call_id,
                            &result.tool_name,
                            None,
                        ),
                    );
                }
                claim.sink.notify(
                    acp::method::SESSION_UPDATE,
                    &acp::tool_call_finished(
                        &claim.thread_id,
                        &result.tool_call_id,
                        result.success,
                        &result.summary,
                    ),
                );
            }
            None => tracing::debug!(
                tool = %result.tool_name,
                "dropping a tool result that belongs to no known turn",
            ),
        }

        // Learning the round pins every *other* call in it, which is how a
        // refused call — one that never announced a start — finds its client.
        if let Some(turn_id) = actor.model.calls.remove(&result.tool_call_id) {
            actor
                .model
                .correlations
                .insert(result.correlation_id.clone(), turn_id);
        }

        Reply::ready()
    });
}

/// Arms an expiry for the claim just admitted, or clears the field.
fn arm_expiry(actor: &mut ManagedActor<Started, TurnRouter>, admitted: bool) {
    if !admitted {
        actor.model.expiry = None;
        return;
    }
    let expiry = actor.handle().send_after(
        ClaimExpired {
            generation: actor.model.generation,
        },
        CLAIM_DEADLINE,
    );
    actor.model.expiry = Some(expiry);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    fn claim(sink: EventSink) -> Claim {
        Claim {
            thread_id: ThreadId::new(),
            turn_id: TurnId::new(),
            sink,
        }
    }

    fn sink() -> (EventSink, mpsc::UnboundedReceiver<String>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (EventSink::new(tx), rx)
    }

    #[test]
    fn settling_with_a_turn_binds_the_claim() {
        let mut router = TurnRouter::default();
        let (sink, _rx) = sink();
        let staked = claim(sink);
        let garrison_turn = staked.turn_id.clone();
        router.outstanding = Some(staked);

        let acton_turn = ActonTurnId::new();
        assert!(router.settle(Some(acton_turn.clone())).is_none());

        assert!(router.outstanding.is_none());
        assert_eq!(
            router.turns.get(&acton_turn).unwrap().turn_id,
            garrison_turn
        );
    }

    #[test]
    fn a_disowned_turn_leaves_an_outstanding_claim_alone() {
        // The race this exists to stop: a completion's `TurnStarted` arriving
        // while a real turn is waiting to be bound.
        let mut router = TurnRouter::default();
        let (sink, _rx) = sink();
        let staked = claim(sink);
        let garrison_turn = staked.turn_id.clone();
        router.outstanding = Some(staked);

        let completion = ActonTurnId::new();
        router.disown(completion.clone());
        assert!(router.is_disowned(&completion));

        // The turn's own start still binds it, and to its own claim.
        let real = ActonTurnId::new();
        router.settle(Some(real.clone()));

        assert_eq!(router.turns.get(&real).unwrap().turn_id, garrison_turn);
        assert!(
            !router.turns.contains_key(&completion),
            "a completion must never appear as a routable turn",
        );
    }

    #[test]
    fn a_turn_that_was_never_disowned_is_still_bound() {
        let mut router = TurnRouter::default();
        let (sink, _rx) = sink();
        router.outstanding = Some(claim(sink));

        let acton_turn = ActonTurnId::new();
        assert!(!router.is_disowned(&acton_turn));
        router.settle(Some(acton_turn.clone()));

        assert!(router.turns.contains_key(&acton_turn));
    }

    #[test]
    fn disowning_is_answered_once_and_then_forgotten() {
        // Consumed on the first ask, so a second turn that happened to reuse
        // the id would route normally rather than vanishing.
        let mut router = TurnRouter::default();
        let turn = ActonTurnId::new();
        router.disown(turn.clone());

        assert!(router.is_disowned(&turn));
        assert!(!router.is_disowned(&turn));
    }

    #[test]
    fn disowned_turns_that_never_start_cannot_grow_without_bound() {
        let mut router = TurnRouter::default();
        let first = ActonTurnId::new();
        router.disown(first.clone());
        for _ in 0..DISOWNED_CAPACITY {
            router.disown(ActonTurnId::new());
        }

        assert_eq!(router.disowned.len(), DISOWNED_CAPACITY);
        assert!(
            !router.is_disowned(&first),
            "the oldest disowned turn is evicted, not the newest",
        );
    }

    #[test]
    fn settling_without_a_turn_discards_the_claim() {
        let mut router = TurnRouter::default();
        let (sink, _rx) = sink();
        router.outstanding = Some(claim(sink));

        assert!(router.settle(None).is_none());

        assert!(router.outstanding.is_none());
        assert!(router.turns.is_empty());
    }

    #[test]
    fn forgetting_a_turn_purges_its_calls_and_rounds() {
        let mut router = TurnRouter::default();
        let (sink, _rx) = sink();
        let acton_turn = ActonTurnId::new();
        let correlation = CorrelationId::new();
        router.turns.insert(acton_turn.clone(), claim(sink));
        router
            .calls
            .insert("call-1".to_string(), acton_turn.clone());
        router
            .correlations
            .insert(correlation.clone(), acton_turn.clone());

        router.forget(&acton_turn);

        assert!(router.turns.is_empty());
        assert!(router.calls.is_empty());
        assert!(router.correlations.is_empty());
    }

    #[test]
    fn a_started_call_routes_by_its_own_identifier() {
        let mut router = TurnRouter::default();
        let (sink, _rx) = sink();
        let acton_turn = ActonTurnId::new();
        let staked = claim(sink);
        let expected = staked.thread_id.clone();
        router.turns.insert(acton_turn.clone(), staked);
        router.calls.insert("call-1".to_string(), acton_turn);

        let routed = router.route_result("call-1", &CorrelationId::new());

        assert_eq!(routed.map(|claim| claim.thread_id.clone()), Some(expected));
    }

    #[test]
    fn a_refused_call_routes_by_its_round() {
        let mut router = TurnRouter::default();
        let (first, _rx1) = sink();
        let (second, _rx2) = sink();
        let correlation = CorrelationId::new();

        let mine = ActonTurnId::new();
        let staked = claim(first);
        let expected = staked.thread_id.clone();
        router.turns.insert(mine.clone(), staked);
        router.correlations.insert(correlation.clone(), mine);

        // A second turn is open, so the single-turn fallback cannot be what
        // answers this.
        router.turns.insert(ActonTurnId::new(), claim(second));

        let routed = router.route_result("never-started", &correlation);

        assert_eq!(routed.map(|claim| claim.thread_id.clone()), Some(expected));
    }

    #[test]
    fn a_lone_turn_claims_an_unattributable_result() {
        let mut router = TurnRouter::default();
        let (sink, _rx) = sink();
        let staked = claim(sink);
        let expected = staked.thread_id.clone();
        router.turns.insert(ActonTurnId::new(), staked);

        let routed = router.route_result("never-started", &CorrelationId::new());

        assert_eq!(routed.map(|claim| claim.thread_id.clone()), Some(expected));
    }

    #[test]
    fn an_unattributable_result_is_dropped_when_turns_are_ambiguous() {
        let mut router = TurnRouter::default();
        let (first, _rx1) = sink();
        let (second, _rx2) = sink();
        router.turns.insert(ActonTurnId::new(), claim(first));
        router.turns.insert(ActonTurnId::new(), claim(second));

        assert!(router
            .route_result("never-started", &CorrelationId::new())
            .is_none());
    }

    /// A two-step plan, published by `turn_id` as call `call-1`.
    fn plan_event(
        turn_id: &ActonTurnId,
        first: acton_ai::tools::plan::PlanStepStatus,
    ) -> PlanUpdated {
        use acton_ai::tools::plan::{Plan, PlanStep, PlanStepStatus};

        let plan = Plan::new(
            vec![
                PlanStep::parse("read the parser", first).unwrap(),
                PlanStep::parse("fix the parser", PlanStepStatus::Pending).unwrap(),
            ],
            None,
        )
        .expect("a two-step plan is valid");

        PlanUpdated {
            turn_id: turn_id.clone(),
            correlation_id: CorrelationId::new(),
            tool_call_id: "call-1".to_string(),
            plan,
        }
    }

    #[test]
    fn a_plan_reaches_only_the_session_that_owns_its_turn() {
        use acton_ai::tools::plan::PlanStepStatus;

        let mut router = TurnRouter::default();
        let (mine, mut rx_mine) = sink();
        let (theirs, mut rx_theirs) = sink();

        let my_turn = ActonTurnId::new();
        let staked = claim(mine);
        let expected = staked.thread_id.clone();
        router.turns.insert(my_turn.clone(), staked);
        router.turns.insert(ActonTurnId::new(), claim(theirs));

        let (sink, update) = router
            .plan_delivery(&plan_event(&my_turn, PlanStepStatus::InProgress))
            .expect("a bound turn's plan must route");
        sink.notify(acp::method::SESSION_UPDATE, &update);

        let line = rx_mine.try_recv().expect("the owner must be told");
        let frame: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(frame["params"]["sessionId"], expected.to_string());
        assert_eq!(frame["params"]["update"]["sessionUpdate"], "plan");
        assert!(
            rx_theirs.try_recv().is_err(),
            "the other session must hear nothing about a plan it did not make"
        );
    }

    #[test]
    fn a_plan_for_a_turn_this_router_never_bound_is_dropped() {
        use acton_ai::tools::plan::PlanStepStatus;

        let mut router = TurnRouter::default();
        let (only, _rx) = sink();
        router.turns.insert(ActonTurnId::new(), claim(only));

        // One turn is open, so the single-turn fallback the *tool result*
        // route allows would deliver this. A plan names its own turn, so
        // there is nothing to fall back to and nothing to deliver.
        assert!(router
            .plan_delivery(&plan_event(&ActonTurnId::new(), PlanStepStatus::Pending))
            .is_none());
    }

    #[test]
    fn a_compaction_notice_reaches_only_the_session_whose_history_shrank() {
        let mut router = TurnRouter::default();
        let (mine, mut rx_mine) = sink();
        let (theirs, mut rx_theirs) = sink();

        let my_turn = ActonTurnId::new();
        let staked = claim(mine);
        let expected = staked.thread_id.clone();
        router.turns.insert(my_turn.clone(), staked);
        router.turns.insert(ActonTurnId::new(), claim(theirs));

        let (sink, notice) = router
            .compaction_delivery(&my_turn, 900, 300, 8)
            .expect("a bound turn's compaction must route");
        sink.notify(acp::ext::SESSION_COMPACTED, &notice);

        let line = rx_mine.try_recv().expect("the owner must be told");
        let frame: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(frame["method"], acp::ext::SESSION_COMPACTED);
        assert_eq!(frame["params"]["sessionId"], expected.to_string());
        assert_eq!(frame["params"]["messagesElided"], 8);
        assert!(rx_theirs.try_recv().is_err());
    }

    #[test]
    fn the_status_reports_the_policy_and_what_it_has_done() {
        let router = TurnRouter {
            compaction: Some(acp::CompactionStatus {
                threshold: 0.8,
                keep_recent_turns: 3,
            }),
            compactions: 2,
            ..TurnRouter::default()
        };

        let status = router.context_status();

        assert_eq!(status.compactions, 2);
        assert_eq!(
            status.compaction.map(|policy| policy.keep_recent_turns),
            Some(3)
        );
    }

    #[test]
    fn a_router_with_no_compaction_policy_says_so() {
        let status = TurnRouter::default().context_status();

        assert!(status.compaction.is_none());
        assert_eq!(status.compactions, 0);
    }

    #[test]
    fn releasing_by_garrison_identifier_is_idempotent() {
        let mut router = TurnRouter::default();
        let (sink, _rx) = sink();
        let staked = claim(sink);
        let garrison_turn = staked.turn_id.clone();
        router.turns.insert(ActonTurnId::new(), staked);

        router.forget_garrison(&garrison_turn);
        router.forget_garrison(&garrison_turn);

        assert!(router.turns.is_empty());
    }
}
