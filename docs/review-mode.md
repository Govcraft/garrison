# Review mode

`garrison-agent review` reads a Bitbucket Data Center pull request, says what
is wrong with it, and exits with a code a pipeline can branch on. It is the
unattended half of Garrison: no terminal, no approvals, no writes.

## Invoking it

```sh
export GARRISON_BITBUCKET_TOKEN="$(cat /run/secrets/bitbucket)"

garrison-agent review \
  --bitbucket https://bitbucket.agency.gov \
  --pull-request AGENCY/benefits-portal/42 \
  --commit "$GIT_COMMIT" \
  --run-url "$BUILD_URL" \
  --post
```

Without `--post` it is a dry run: it reviews, prints, and touches nothing.
That is the right first invocation against a repository anyone cares about.

The credential comes from the environment and is deliberately not a flag. A
token in `argv` is readable by every process on the runner and is echoed into
most CI logs.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | The review ran. Findings may have been posted; nothing blocked. |
| 1 | The review did not happen. The answer could not be read as a review. |
| 2 | It refused to start: a malformed `--pull-request`, no credential. |
| 3 | `--enforce` was set and a blocker-severity finding was found. |

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
  environment { GARRISON_BITBUCKET_TOKEN = credentials('bitbucket-review-token') }
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

## Open questions, and the defaults in force

Issue #16 raised four. Three are settled in the code; one is not.

1. **DC or Cloud** — Data Center. Different products with different REST
   surfaces and auth, and the on-premises posture is DC's.
2. **Does a pipeline run consume a seat?** — **Unsettled.** Nothing in review
   mode consumes or checks a seat today. The review is attributed to the
   install that ran it, and seat enforcement stays where #12 puts it. This is
   a placeholder, not a decision: charging a seat per build agent would be
   surprising, and attributing every review to the pull request's author
   complicates revocation. Whoever settles #12 should settle this with it.
3. **Which credential?** — A short-lived bearer token from the environment.
   The install key never leaves the runner and is not used here.
4. **What does a finding block?** — Nothing, by default. See advisory above.

## What is not built

- **Audit shipping from an ephemeral runner.** #16 names #8 as a hard
  dependency: a trail written to a runner's local disk dies with the
  container. Review mode does not yet ship its trail, so a review performed in
  CI currently leaves evidence only where the runner kept it. This is the
  largest remaining gap and it is a real one.
- **Policy distribution to a pipeline install** (#11), so a build agent runs
  the organization's policy rather than whatever the repository ships.
- **Reviewing anything that is not a Bitbucket pull request.** A local
  `git diff` mode would reuse everything except the transport, and the prompt
  layer is already independent of Bitbucket for that reason.
