# Review mode

`garrison-agent review` reads a Bitbucket Data Center pull request, says what
is wrong with it, and exits with a code a pipeline can branch on. It is the
unattended half of Garrison: no terminal, no approvals, no writes.

## It is experimental, and it refuses until you say so

Review mode ships in the binary and is off. Asking for it without enabling it
is a refusal to start (exit 2) naming both ways to switch it on:

```sh
export GARRISON_EXPERIMENTAL=review          # for one invocation, or
# [experimental]
# review = true                              # in garrison.toml
```

Enabling it accepts a narrower promise than the rest of the binary makes: its
behaviour, its output, and the exit codes below may change without a major
version bump. Everything else keeps its usual contract.

The refusal is the point. A warning is read once and then filtered out of CI
logs, so it would not stop a pipeline coming to depend on codes that are still
moving. A refusal is read every time until somebody decides, and the decision
leaves a trace an auditor can find: a line in `garrison.toml`, or a variable in
the job definition. When it is on, every run prints a one-line notice to
stderr.

## Invoking it

```sh
export GARRISON_EXPERIMENTAL=review
export GARRISON_BITBUCKET_TOKEN="$(cat /run/secrets/bitbucket)"

garrison-agent review \
  --bitbucket https://bitbucket.agency.gov \
  --pull-request AGENCY/benefits-portal/42 \
  --commit "$GIT_COMMIT" \
  --run-url "$BUILD_URL" \
  --audit-timeout 60 \
  --post
```

Without `--post` it is a dry run: it reviews, prints, and touches nothing.
That is the right first invocation against a repository anyone cares about.

The credential comes from the environment and is deliberately not a flag. A
token in `argv` is readable by every process on the runner and is echoed into
most CI logs.

## Exit codes

| Code | Meaning | Who should look |
|------|---------|-----------------|
| 0 | The review ran. Findings may have been posted; nothing blocked. | Nobody |
| 1 | The review did not happen. The answer could not be read as a review. | An operator |
| 2 | It refused to start: not enabled, a malformed `--pull-request`, no credential. | Whoever wired the pipeline |
| 3 | `--enforce` was set and a blocker-severity finding was found. | A developer |
| 5 | The review ran but its audit trail never reached the control plane. | An operator |

Codes 3 and 5 are deliberately distinct. One says the code under review has a
problem; the other says the review itself cannot be proven to have happened.
Collapsing them would route every shipping outage to a developer who has
nothing to fix.

The distinction between 0 and 1 is the one that matters. **An answer that
could not be parsed is not a clean review.** A pipeline that treated it as one
would put a green check on code nobody looked at, which is worse than having
no reviewer, because now there is evidence of a review that did not happen.
Exit 1 is not excused by advisory mode: advisory is a promise about findings,
not a promise to report success when the run failed.

## Advisory by default

Findings are posted; the build passes. `--enforce` changes that, and only for
`blocker` severity.

This is deliberate. Failing a build on a model's opinion is a strong claim,
and a reviewer that makes it in week one gets switched off in week two. Run it
advisory, read what it says for a while, and turn on enforcement when the team
believes it.

Advisory mode also downgrades the comments themselves. A Bitbucket `BLOCKER`
comment is an unresolved task, which gates a merge no matter what the build
status says, so advisory posts everything as `NORMAL`. Otherwise the setting
would not do what its name claims.

## What it refuses

Every tool call. Review mode is read-only, and a pipeline has nobody to answer
a permission prompt. The alternative on the table was auto-approval; refusing
is the honest one. A review that needed to write to do its job was not a
review.

This is not configurable, and there is no flag that relaxes it.

## Where findings land

A finding names a file and a line from the excerpt it was shown. That margin
is not the file's line numbering, since the excerpt is only the changed
regions, so it is resolved back to a real destination line before anchoring.

A finding whose line cannot be resolved is **still posted**, as a comment on
the pull request itself, saying where it was meant to go. A real defect with a
bad line number is still a real defect. The run reports how many landed that
way, because a review where several findings would not anchor is one whose
line numbers should be distrusted.

Every comment is signed `Posted by Garrison review.` A reader must never have
to guess whether a comment came from a colleague or a model, and an
attribution that appears only sometimes teaches readers that unmarked comments
are human.

## Wiring it into CI

Bitbucket **Pipelines** is a Cloud feature. Data Center has no built-in CI, so
in practice this runs from Bamboo, Jenkins, GitLab CI, or whatever the agency
already operates. That is why the entry point is a plain command with an exit
code rather than a provider-specific plugin.

A Jenkins declarative stage, as an example:

```groovy
stage('Garrison review') {
  environment {
    GARRISON_EXPERIMENTAL = 'review'
    GARRISON_BITBUCKET_TOKEN = credentials('bitbucket-review-token')
  }
  steps {
    sh '''
      garrison-agent review \
        --bitbucket https://bitbucket.agency.gov \
        --pull-request "${PROJECT}/${REPO}/${CHANGE_ID}" \
        --commit "${GIT_COMMIT}" \
        --run-url "${BUILD_URL}" \
        --post
    '''
  }
}
```

## The four questions #16 raised, and how each is answered

1. **DC or Cloud** — Data Center. Different products with different REST
   surfaces and auth, and the on-premises posture is DC's.
2. **Does a pipeline run consume a seat?** — Yes, the runner install's own,
   and this is settled by construction rather than by a rule written for
   review mode. `review` is a client: it connects to the daemon, opens a
   session, and sends a prompt. That prompt is an ordinary turn, so it passes
   the same gates every turn passes, and the seat monitor is one of them. A
   revoked seat refuses the review with `SEAT_REFUSED` exactly as it refuses a
   turn typed into a terminal.

   The alternative was a per-review exemption, and building one would have
   meant a path on which work reaches a model without a live seat behind it.
   Nothing in review mode gets to be that path. The consequence worth stating
   plainly: a build agent is a seat, so a fleet of runners is a fleet of
   seats, and that is a licensing fact an agency should know before wiring
   this into every repository.
3. **Which credential?** — A short-lived bearer token from the environment.
   The install key never leaves the runner and is not used here.
4. **What does a finding block?** — Nothing, by default. See advisory above.

## The trail has to leave before the runner does

This is the part a CI review gets wrong by default, and it is worth stating
why rather than just documenting the flag.

Garrison's general shipping policy is built on one assumption: the trail file
is a durable buffer. An unreachable control plane never stops a turn, because
a laptop on a train catches up when it lands, and a daemon that refused to
work whenever a VPN dropped would be switched off within a week.

That assumption is false in a container. The runner is deleted minutes after
the review ends, so an entry still sitting in its buffer is not delayed
evidence, it is destroyed evidence. Identical status fields, opposite meaning.

So `review` waits for the plane to accept the trail before it exits, and exits
5 when it could not. `--audit-timeout` bounds the wait (30 seconds by default)
and `--allow-unshipped-audit` downgrades the failure to a warning, which is
right on a workstation and wrong on a runner.

Two subtleties the implementation handles, both of which would otherwise
produce a confident green check:

- **An empty backlog is not proof.** A turn's last entries are sealed
  asynchronously, so a backlog of zero one millisecond after the turn can mean
  "nothing written yet" rather than "everything shipped". The drain requires
  the backlog to be empty *and* the trail head to have stopped moving between
  observations.
- **A halt is not waited out.** If the plane refused an entry as forked, or
  the credential was rejected, the drain stops immediately rather than
  spending the remaining timeout learning nothing.

When the trail does not make it, the build status on the pull request says so
too. A green mark on a review whose evidence died with the container would be
precisely the claim Garrison exists not to make.

## What is not built

- **An install identity that is legitimately ephemeral** (#11). Note what this
  is *not*: policy distribution already works here. The runner's daemon pulls
  its assigned bundle from the plane, re-verifies the checksum against the
  rows it received, and puts it in force before any turn, and a review's turn
  is governed by that bundle like any other. Nothing about delivery is
  review-specific or missing.

  What is missing is upstream of the bundle. Enrollment is one-time and
  durable on purpose: a daemon is enrolled if and only if it can read back its
  install record, the packet is destroyed the moment it is spent, and the
  signing key is generated on the machine and never transmitted. A container
  has no durable disk, so every build is a first run. That gives either one
  install row per build, which makes the fleet view and the seat count
  meaningless, or a spent packet and a refusal to start, which is the right
  behaviour and a broken pipeline.

  The workaround today is to mount a provisioned install record and key into
  the runner image. It works, and it costs a long-lived private key living in
  an image and every concurrent build sharing one identity and one seat. The
  real fix is a control-plane question rather than an agent one: a grant that
  mints a short-lived identity per build, or an install kind provisioned once
  and permitted to run concurrently.
- **Reviewing anything that is not a Bitbucket pull request.** A local
  `git diff` mode would reuse everything except the transport, and the prompt
  layer is already independent of Bitbucket for that reason.
