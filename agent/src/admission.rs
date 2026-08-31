//! Turn admission: one question every gate answers the same way.
//!
//! Before a session runs a turn it asks each of its gates [`AdmitTurn`], in
//! order, and stops at the first refusal. A gate is any actor that implements
//! a handler for [`AdmitTurn`]: a seat monitor, a policy agent, an audit
//! shipper, a session store. None of them touch `thread.rs`; they are handed
//! to a session as a list, and the fold here is the only code that walks it.
//!
//! # Two kinds of work, one list of gates
//!
//! An inline completion is a paid model call that sends code to a provider, so
//! it crosses these gates too. It is not a turn a person asked for, though, and
//! a rule about an interrupted turn has nothing to say about a keystroke. The
//! request carries a [`Work`] saying which it is, and every gate answers for
//! both rather than a caller deciding which gates a completion deserves.
//!
//! # Fail closed
//!
//! A gate that cannot be asked — its actor has stopped, its reply never comes,
//! the deadline passes — has not said yes. [`admit`] treats every
//! [`AskError`] as a refusal, because a gate that exists in the list is a gate
//! somebody decided a turn must pass, and a turn that runs because the gate was
//! unreachable is a turn nobody admitted.
//!
//! # One refusal vocabulary
//!
//! [`TurnRefusal`] is the closed set of reasons a turn may be refused, and
//! [`refusal_code`] is the one place a refusal becomes a JSON-RPC error code.
//! Every gate speaks it, so a client sees the same error shape whichever gate
//! said no.

use crate::protocol::jsonrpc::error_code;
use crate::types::{ThreadId, TurnId};
use acton_reactive::prelude::*;
use std::fmt;
use std::time::Duration;

/// How long a gate has to answer before its silence counts as a refusal.
///
/// Well inside acton-reactive's default `ask` deadline, so a wedged gate turns
/// into a prompt error rather than a `session/prompt` that hangs for the
/// runtime-wide thirty seconds.
pub const GATE_DEADLINE: Duration = Duration::from_secs(5);

/// What kind of work a gate is being asked to admit.
///
/// Every gate is asked about both kinds, and each decides for itself what its
/// own rule means for each. The alternative was a second, shorter gate list
/// that the completion path walks instead, and it was rejected: it puts the
/// judgment about completions in the code that assembles the list rather than
/// in the gate that holds the rule, and a gate added later would join that
/// list by being forgotten rather than by being considered. Here, a new gate
/// cannot compile without answering for both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Work {
    /// A turn a person asked for, through `session/prompt`.
    Turn,
    /// An inline completion at a cursor, through `_garrison/complete`.
    ///
    /// Speculative, discarded when it is slow, and running no tools. It is
    /// still a paid model call that sends the code around a cursor to a
    /// provider, on every typing pause, which is the whole reason it is put to
    /// the gates rather than trusted to the ownership check alone.
    Completion,
}

/// Asks a gate whether work may start.
#[acton_message]
pub struct AdmitTurn {
    /// The session about to run the work.
    pub thread_id: ThreadId,
    /// Garrison's identifier for the turn the work runs under.
    pub turn_id: TurnId,
    /// Which kind of work this is. See [`Work`].
    pub work: Work,
}

/// A gate's answer.
#[acton_message]
#[derive(PartialEq, Eq)]
pub enum Admission {
    /// The turn may start, as far as this gate is concerned.
    Admit,
    /// It may not, and this is why.
    Refuse(TurnRefusal),
}

impl Request for AdmitTurn {
    type Response = Admission;
}

/// Why a turn was not admitted.
///
/// Non-exhaustive: a later gate may need a reason not listed here, and adding
/// one must not break the clients that already match on these.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TurnRefusal {
    /// The operator holds no seat that entitles this install to run.
    Seat {
        /// What the seat check found.
        reason: String,
    },
    /// The control plane could not be reached and the grace for running
    /// without it has run out.
    PlaneUnavailable {
        /// What failed, in transport terms.
        reason: String,
    },
    /// The policy in force forbids the turn.
    Policy {
        /// Which rule, or why there is no usable policy.
        reason: String,
    },
    /// The audit trail cannot be shipped and the unshipped backlog is past its
    /// bound.
    AuditShipping {
        /// What the shipper is stuck on.
        reason: String,
    },
    /// The local audit writer cannot promise this turn will be recorded, and
    /// the trail is strict.
    ///
    /// Distinct from [`Self::AuditShipping`], which is about the copy the
    /// control plane holds: this one is about the trail on this machine, and
    /// it is refused before the turn starts rather than after a tool has
    /// already run unrecorded. Both report under the same JSON-RPC code,
    /// because a client's remedy is the same — stop, and look at the audit
    /// section of `_garrison/status`.
    AuditDegraded {
        /// What the writer is stuck on, and what an operator does about it.
        reason: String,
    },
    /// The session store the turn would be recorded in is unavailable.
    StoreUnavailable,
    /// The session has an interrupted turn that must be resumed or abandoned
    /// before a new one starts.
    TurnInterrupted {
        /// The turn left half-done.
        turn_id: TurnId,
    },
    /// A gate could not be asked at all, so it has not said yes.
    GateUnreachable {
        /// Which gate, by actor identity.
        gate: String,
        /// What went wrong asking it.
        reason: String,
    },
}

impl TurnRefusal {
    /// The stable word the audit trail records as the refusal's decision.
    ///
    /// [`fmt::Display`] renders a refusal for a human reading an error; this
    /// renders it for a machine filtering a year of trails. They are separate
    /// on purpose: the prose may be reworded whenever it reads badly, and an
    /// auditor's saved query must not break when it is. Every arm answers a
    /// fixed lowercase word, and an arm added later adds a word rather than
    /// changing one.
    #[must_use]
    pub const fn decision(&self) -> &'static str {
        match self {
            Self::Seat { .. } => "seat",
            Self::PlaneUnavailable { .. } => "plane_unavailable",
            Self::Policy { .. } => "policy",
            Self::AuditShipping { .. } => "audit_shipping",
            Self::AuditDegraded { .. } => "audit_degraded",
            Self::StoreUnavailable => "store_unavailable",
            Self::TurnInterrupted { .. } => "turn_interrupted",
            Self::GateUnreachable { .. } => "gate_unreachable",
        }
    }
}

impl fmt::Display for TurnRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Seat { reason } => write!(f, "no seat entitles this turn: {reason}"),
            Self::PlaneUnavailable { reason } => {
                write!(f, "the control plane is unreachable: {reason}")
            }
            Self::Policy { reason } => write!(f, "policy refuses this turn: {reason}"),
            Self::AuditShipping { reason } => {
                write!(f, "the audit trail cannot be shipped: {reason}")
            }
            Self::AuditDegraded { reason } => {
                write!(f, "this turn cannot be recorded: {reason}")
            }
            Self::StoreUnavailable => write!(f, "the session store is unavailable"),
            Self::TurnInterrupted { turn_id } => write!(
                f,
                "turn {turn_id} was interrupted and must be resumed or abandoned first"
            ),
            Self::GateUnreachable { gate, reason } => {
                write!(f, "gate {gate} could not be asked: {reason}")
            }
        }
    }
}

/// The JSON-RPC error code a refusal is reported under.
///
/// Pure, and the only mapping from a refusal to a code; the table it encodes
/// is the one frozen in [`error_code`]. An unreachable gate is not a verdict
/// any subsystem reached, so it reports as the turn failing rather than as any
/// of the governance refusals.
#[must_use]
pub const fn refusal_code(refusal: &TurnRefusal) -> i32 {
    match refusal {
        TurnRefusal::Seat { .. } => error_code::SEAT_REFUSED,
        TurnRefusal::PlaneUnavailable { .. } => error_code::PLANE_UNREACHABLE,
        TurnRefusal::Policy { .. } => error_code::POLICY_REFUSED,
        TurnRefusal::AuditShipping { .. } | TurnRefusal::AuditDegraded { .. } => {
            error_code::AUDIT_SHIPPING_REFUSED
        }
        TurnRefusal::StoreUnavailable => error_code::STORE_UNAVAILABLE,
        TurnRefusal::TurnInterrupted { .. } => error_code::TURN_INTERRUPTED,
        TurnRefusal::GateUnreachable { .. } => error_code::TURN_FAILED,
    }
}

/// Folds a sequence of answers into one: the first refusal wins.
///
/// Pure. The iterator is consumed lazily, so a caller that produces answers by
/// asking gates one at a time stops asking once one has refused.
pub fn fold(admissions: impl IntoIterator<Item = Admission>) -> Admission {
    admissions
        .into_iter()
        .find(|admission| matches!(admission, Admission::Refuse(_)))
        .unwrap_or(Admission::Admit)
}

/// Asks every gate in order, stopping at the first refusal.
///
/// Empty gates admit. A gate that cannot be asked refuses; see the module docs.
pub async fn admit(gates: &[ActorHandle], request: &AdmitTurn) -> Admission {
    admit_within(gates, request, GATE_DEADLINE).await
}

/// [`admit`], with a deadline the caller chooses.
///
/// The completion path asks for a tighter one than [`GATE_DEADLINE`]. A
/// completion is abandoned after two seconds, so a gate given five could spend
/// the entire budget and still decide nothing, and the latency this path exists
/// to protect would be spent on the gates rather than on the model. A gate that
/// misses the shorter deadline refuses exactly as it would miss the longer one:
/// a completion nobody admitted is not shown.
pub async fn admit_within(
    gates: &[ActorHandle],
    request: &AdmitTurn,
    deadline: Duration,
) -> Admission {
    for gate in gates {
        let answer = match gate.ask_with_timeout(request.clone(), deadline).await {
            Ok(answer) => answer,
            Err(error) => Admission::Refuse(TurnRefusal::GateUnreachable {
                gate: gate.id().to_string(),
                reason: describe_ask_error(&error),
            }),
        };
        if let Admission::Refuse(refusal) = answer {
            tracing::info!(
                gate = %gate.id(),
                thread_id = %request.thread_id,
                turn_id = %request.turn_id,
                work = ?request.work,
                %refusal,
                "a gate refused a turn",
            );
            return Admission::Refuse(refusal);
        }
    }
    Admission::Admit
}

/// Words for an `AskError`, since the type does not print itself.
fn describe_ask_error(error: &AskError) -> String {
    match error {
        AskError::Undeliverable => "the gate has stopped".to_string(),
        AskError::Cancelled => "the ask was cancelled by shutdown".to_string(),
        AskError::NoReply => "the gate did not answer".to_string(),
        AskError::TimedOut { after } => {
            format!("the gate did not answer within {}s", after.as_secs())
        }
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refuse(reason: &str) -> Admission {
        Admission::Refuse(TurnRefusal::Policy {
            reason: reason.to_string(),
        })
    }

    #[test]
    fn no_answers_admit() {
        assert!(matches!(fold(Vec::new()), Admission::Admit));
    }

    #[test]
    fn all_admits_admit() {
        assert!(matches!(
            fold([Admission::Admit, Admission::Admit]),
            Admission::Admit
        ));
    }

    #[test]
    fn the_first_refusal_wins_over_later_ones() {
        let folded = fold([Admission::Admit, refuse("first"), refuse("second")]);

        assert_eq!(
            folded,
            Admission::Refuse(TurnRefusal::Policy {
                reason: "first".to_string()
            })
        );
    }

    #[test]
    fn folding_stops_at_the_first_refusal() {
        // A panicking third element proves it was never reached.
        let answers =
            [refuse("stop here"), Admission::Admit]
                .into_iter()
                .chain(std::iter::from_fn(|| -> Option<Admission> {
                    panic!("asked past the refusal")
                }));

        assert!(matches!(fold(answers), Admission::Refuse(_)));
    }

    #[test]
    fn every_refusal_maps_onto_the_frozen_code_table() {
        let cases = [
            (
                TurnRefusal::Seat {
                    reason: String::new(),
                },
                error_code::SEAT_REFUSED,
            ),
            (
                TurnRefusal::PlaneUnavailable {
                    reason: String::new(),
                },
                error_code::PLANE_UNREACHABLE,
            ),
            (
                TurnRefusal::Policy {
                    reason: String::new(),
                },
                error_code::POLICY_REFUSED,
            ),
            (
                TurnRefusal::AuditShipping {
                    reason: String::new(),
                },
                error_code::AUDIT_SHIPPING_REFUSED,
            ),
            (
                TurnRefusal::AuditDegraded {
                    reason: String::new(),
                },
                error_code::AUDIT_SHIPPING_REFUSED,
            ),
            (TurnRefusal::StoreUnavailable, error_code::STORE_UNAVAILABLE),
            (
                TurnRefusal::TurnInterrupted {
                    turn_id: TurnId::new(),
                },
                error_code::TURN_INTERRUPTED,
            ),
            (
                TurnRefusal::GateUnreachable {
                    gate: String::new(),
                    reason: String::new(),
                },
                error_code::TURN_FAILED,
            ),
        ];

        for (refusal, expected) in cases {
            assert_eq!(refusal_code(&refusal), expected, "{refusal}");
        }
    }

    #[test]
    fn a_refusal_reads_as_a_sentence_with_its_reason() {
        let refusal = TurnRefusal::Seat {
            reason: "seat revoked".to_string(),
        };

        assert_eq!(
            refusal.to_string(),
            "no seat entitles this turn: seat revoked"
        );
    }

    /// A gate that always says no.
    #[acton_actor]
    struct Refuser;

    /// A gate that always says yes.
    #[acton_actor]
    struct Admitter;

    /// A gate that never answers.
    #[acton_actor]
    struct Mute;

    fn request() -> AdmitTurn {
        AdmitTurn {
            thread_id: ThreadId::new(),
            turn_id: TurnId::new(),
            work: Work::Turn,
        }
    }

    async fn spawn_gates(runtime: &mut ActorRuntime) -> (ActorHandle, ActorHandle, ActorHandle) {
        let mut admitter = runtime.new_actor::<Admitter>();
        admitter.act_on::<AdmitTurn>(|_, envelope| {
            let reply = envelope.reply_envelope();
            Reply::pending(async move { reply.send(Admission::Admit).await })
        });

        let mut refuser = runtime.new_actor::<Refuser>();
        refuser.act_on::<AdmitTurn>(|_, envelope| {
            let reply = envelope.reply_envelope();
            Reply::pending(async move {
                reply
                    .send(Admission::Refuse(TurnRefusal::StoreUnavailable))
                    .await;
            })
        });

        let mut mute = runtime.new_actor::<Mute>();
        mute.act_on::<AdmitTurn>(|_, _| Reply::ready());

        (
            admitter.start().await,
            refuser.start().await,
            mute.start().await,
        )
    }

    #[tokio::test]
    async fn no_gates_admit() {
        assert!(matches!(admit(&[], &request()).await, Admission::Admit));
    }

    #[tokio::test]
    async fn a_refusing_gate_refuses_the_turn_even_after_an_admitting_one() {
        let mut runtime = ActonApp::launch_async().await;
        let (admitter, refuser, _) = spawn_gates(&mut runtime).await;

        let answer = admit(&[admitter, refuser], &request()).await;

        assert_eq!(answer, Admission::Refuse(TurnRefusal::StoreUnavailable));
        runtime.shutdown_all().await.expect("clean shutdown");
    }

    #[tokio::test]
    async fn a_gate_that_does_not_answer_is_a_refusal() {
        let mut runtime = ActonApp::launch_async().await;
        let (admitter, _, mute) = spawn_gates(&mut runtime).await;

        let answer = admit(&[mute, admitter], &request()).await;

        assert!(
            matches!(
                answer,
                Admission::Refuse(TurnRefusal::GateUnreachable { .. })
            ),
            "{answer:?}"
        );
        runtime.shutdown_all().await.expect("clean shutdown");
    }

    #[tokio::test]
    async fn a_completion_is_refused_by_the_same_gate_a_turn_is() {
        // The whole point of #22: naming work a completion must not be a way
        // past a gate. Only a gate that opts out for itself may admit one.
        let mut runtime = ActonApp::launch_async().await;
        let (_, refuser, _) = spawn_gates(&mut runtime).await;

        let completion = AdmitTurn {
            work: Work::Completion,
            ..request()
        };
        let answer = admit(&[refuser], &completion).await;

        assert_eq!(answer, Admission::Refuse(TurnRefusal::StoreUnavailable));
        runtime.shutdown_all().await.expect("clean shutdown");
    }

    #[tokio::test]
    async fn a_short_deadline_refuses_a_silent_gate_without_waiting_the_long_one() {
        // A completion is abandoned after two seconds, so a gate given the
        // full five would decide nothing and cost everything.
        let mut runtime = ActonApp::launch_async().await;
        let (_, _, mute) = spawn_gates(&mut runtime).await;

        let started = std::time::Instant::now();
        let answer = admit_within(&[mute], &request(), Duration::from_millis(50)).await;
        let waited = started.elapsed();

        assert!(
            matches!(
                answer,
                Admission::Refuse(TurnRefusal::GateUnreachable { .. })
            ),
            "{answer:?}"
        );
        assert!(
            waited < GATE_DEADLINE,
            "the caller's deadline must be the one honoured, waited {waited:?}",
        );
        runtime.shutdown_all().await.expect("clean shutdown");
    }

    #[tokio::test]
    async fn a_stopped_gate_is_a_refusal() {
        let mut runtime = ActonApp::launch_async().await;
        let (admitter, _, _) = spawn_gates(&mut runtime).await;
        admitter.stop().await.expect("the gate stops");

        let answer = admit(&[admitter], &request()).await;

        assert!(
            matches!(
                answer,
                Admission::Refuse(TurnRefusal::GateUnreachable { .. })
            ),
            "{answer:?}"
        );
        runtime.shutdown_all().await.expect("clean shutdown");
    }
}
