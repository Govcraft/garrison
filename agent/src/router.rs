//! Attributing acton-ai's broadcast tool events to the client that caused them.
//!
//! # The problem this actor exists to solve
//!
//! acton-ai broadcasts a turn's tool lifecycle — [`TurnLifecycle::ToolStarted`]
//! and [`LLMStreamToolResult`] — to the runtime-wide broker, keyed by an
//! `acton_ai::types::TurnId` that the prompt loop mints internally. A caller of
//! `collect()` is never told that identifier, and no callback carries it. One
//! process serving several clients therefore receives every client's tool
//! events on one channel with no way to tell them apart.
//!
//! Approvals do not have this problem: they run on the turn's own task, so
//! [`crate::approval`] identifies them exactly with a task-local. Only the
//! broadcast events, which arrive on the broker's task, need a registry.
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
use crate::types::{ThreadId, TurnId};
use acton_ai::messages::{LLMStreamToolResult, TurnLifecycle};
use acton_ai::types::{CorrelationId, TurnId as ActonTurnId};
use acton_reactive::prelude::*;
use std::collections::{HashMap, VecDeque};
use std::time::Duration;

/// How long an outstanding claim may go unbound before it is released.
///
/// Enormous next to the microseconds the window actually takes; short enough
/// that a wedged claim cannot stall turn starts for a whole session.
pub const CLAIM_DEADLINE: Duration = Duration::from_secs(10);

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
}

impl TurnRouter {
    /// Spawns the router and subscribes it to the two events it routes.
    ///
    /// Subscriptions go on the builder, before `start`: registering them
    /// afterwards is silently ignored and would leave a router that runs
    /// happily and routes nothing.
    pub async fn spawn(runtime: &mut ActorRuntime) -> ActorHandle {
        let mut builder = runtime.new_actor_with_name::<Self>("turn_router".to_string());

        configure_handlers(&mut builder);

        builder.handle().subscribe::<TurnLifecycle>().await;
        builder.handle().subscribe::<LLMStreamToolResult>().await;

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
            TurnLifecycle::TurnStarted { turn_id } => {
                // No announcement: ACP has no "turn started" event, and the
                // client already knows — it is the one holding the open
                // `session/prompt` request this turn answers.
                next = actor.model.settle(Some(turn_id.clone()));
                arm_expiry(actor, next.is_some());
            }
            TurnLifecycle::TurnRefused => {
                next = actor.model.settle(None);
                arm_expiry(actor, next.is_some());
            }
            TurnLifecycle::TurnFinished { turn_id } => actor.model.forget(turn_id),
            TurnLifecycle::ToolStarted {
                turn_id,
                tool_call_id,
                tool_name,
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
        }

        Reply::pending(async move {
            if let Some(reply) = next {
                reply.send(TurnClaimed).await;
            }
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
