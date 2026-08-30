//! The three calls, over a real socket.
//!
//! # Why there is no Bitbucket container here
//!
//! The obvious shape for this file is testcontainers standing up
//! `atlassian/bitbucket` and driving the real REST API. That was tried, and it
//! does not work, for a reason no amount of test engineering removes.
//!
//! A fresh Bitbucket Data Center container boots to `{"state":"FIRST_RUN"}`
//! and serves `/rest/api/1.0/application-properties` unauthenticated — that
//! much is real, and the version string in `error.rs`'s fixture was recorded
//! from it. Every other endpoint answers `401`, and there is no account to
//! authenticate as until the setup wizard finishes. Step two of that wizard is
//! "Licensing and settings": a required `license` field and a link to
//! my.atlassian.com to generate a key. There is no unlicensed mode, no
//! evaluation bypass, and no way for a hermetic test to obtain a key.
//!
//! So a container buys a 1.2 GB pull and a two-minute boot to reach a login
//! page. The tests below use an in-process mock server instead: still a real
//! HTTP listener on a real port, still reqwest's actual client doing actual
//! TLS-less HTTP, but no image and no skip.
//!
//! # What this proves, and what it does not
//!
//! Proved: the client sends the method, path, query, headers and JSON body
//! this crate believes Bitbucket wants, and turns each status into the right
//! [`BitbucketError`] variant.
//!
//! **Not** proved: that Bitbucket agrees. These expectations are this crate's
//! model of the DC 10 REST API, checked against Atlassian's published
//! reference, not against a running instance. A contract test catches a client
//! that drifts from its own model; it cannot catch a model that was wrong from
//! the start.
//!
//! Closing that gap needs a licensed instance, which is an operator's to
//! provide and not a test's to conjure. When Garrison is pointed at a real DC
//! for the first time, these are the expectations to check first.

use garrison_bitbucket::{
    BitbucketError, BuildState, BuildStatus, Client, Comment, Credentials, PullRequest, Severity,
};
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn pull_request() -> PullRequest {
    PullRequest {
        project: "AGENCY".into(),
        repository: "benefits-portal".into(),
        id: 42,
    }
}

fn client(server: &MockServer) -> Client {
    Client::new(&server.uri(), Credentials::Bearer("tok-abc".into())).unwrap()
}

const DIFF_BODY: &str = r#"{
  "diffs": [{
    "source": {"toString": "src/handler.rs"},
    "destination": {"toString": "src/handler.rs"},
    "hunks": [{
      "segments": [
        {"type": "CONTEXT", "lines": [{"source": 4, "destination": 4, "line": "fn handle() {"}]},
        {"type": "ADDED", "lines": [{"source": 4, "destination": 5, "line": "  let raw = input;"}]}
      ]
    }],
    "truncated": false
  }]
}"#;

#[tokio::test]
async fn fetching_a_diff_asks_for_the_path_and_context_bitbucket_expects() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(
            "/rest/api/1.0/projects/AGENCY/repos/benefits-portal/pull-requests/42/diff",
        ))
        // Context lines are not cosmetic: without them a reviewer reads added
        // lines with no surrounding code.
        .and(query_param("contextLines", "10"))
        .and(header("authorization", "Bearer tok-abc"))
        .respond_with(ResponseTemplate::new(200).set_body_string(DIFF_BODY))
        .expect(1)
        .mount(&server)
        .await;

    let files = client(&server)
        .pull_request_diff(&pull_request(), 10)
        .await
        .expect("the diff should parse");

    assert_eq!(files.len(), 1);
    assert_eq!(files[0].path, "src/handler.rs");
    assert!(files[0].destination_text().contains("let raw = input;"));
}

#[tokio::test]
async fn a_blocker_comment_carries_the_open_state_bitbucket_requires() {
    let server = MockServer::start().await;

    // A BLOCKER without `state: OPEN` is rejected by Bitbucket, and the
    // pairing is not discoverable from the field names. This assertion is the
    // only thing standing between that and a review whose blockers vanish.
    Mock::given(method("POST"))
        .and(path(
            "/rest/api/1.0/projects/AGENCY/repos/benefits-portal/pull-requests/42/comments",
        ))
        .and(body_json(serde_json::json!({
            "text": "this input is not validated",
            "severity": "BLOCKER",
            "state": "OPEN",
            "anchor": {
                "line": 5,
                "lineType": "ADDED",
                "fileType": "TO",
                "path": "src/handler.rs",
                "diffType": "COMMIT"
            }
        })))
        .respond_with(ResponseTemplate::new(201).set_body_string("{}"))
        .expect(1)
        .mount(&server)
        .await;

    let files = garrison_bitbucket::parse_diff(DIFF_BODY).unwrap();
    let anchor = garrison_bitbucket::Anchor::for_line(&files[0], 5).expect("line 5 was added");

    client(&server)
        .post_comment(
            &pull_request(),
            &Comment {
                text: "this input is not validated".into(),
                anchor: Some(anchor),
                severity: Severity::Blocker,
            },
        )
        .await
        .expect("the comment should post");
}

#[tokio::test]
async fn a_comment_with_no_anchor_posts_against_the_pull_request_itself() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path(
            "/rest/api/1.0/projects/AGENCY/repos/benefits-portal/pull-requests/42/comments",
        ))
        // No `anchor` key and no `state`: a NORMAL comment on the pull request
        // as a whole, which is where a run's summary goes.
        .and(body_json(serde_json::json!({
            "text": "reviewed 3 files",
            "severity": "NORMAL"
        })))
        .respond_with(ResponseTemplate::new(201).set_body_string("{}"))
        .expect(1)
        .mount(&server)
        .await;

    client(&server)
        .post_comment(
            &pull_request(),
            &Comment {
                text: "reviewed 3 files".into(),
                anchor: None,
                severity: Severity::Normal,
            },
        )
        .await
        .expect("the summary should post");
}

#[tokio::test]
async fn a_build_status_goes_to_the_build_status_api_not_the_core_one() {
    let server = MockServer::start().await;

    // Different API root, keyed by commit rather than pull request. Getting
    // this wrong yields a 404 that looks like a missing pull request.
    Mock::given(method("POST"))
        .and(path("/rest/build-status/1.0/commits/deadbeefcafe"))
        .and(body_json(serde_json::json!({
            "key": "garrison-review",
            "state": "FAILED",
            "url": "https://ci.agency.gov/runs/9",
            "name": "Garrison review",
            "description": "1 blocker"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    client(&server)
        .set_build_status(
            "deadbeefcafe",
            &BuildStatus {
                key: "garrison-review".into(),
                state: BuildState::Failed,
                url: "https://ci.agency.gov/runs/9".into(),
                name: "Garrison review".into(),
                description: "1 blocker".into(),
            },
        )
        .await
        .expect("the status should post");
}

#[tokio::test]
async fn a_rejected_credential_is_fatal_rather_than_retried() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401).set_body_string(
            r#"{"errors":[{"message":"You are not permitted to access this resource"}]}"#,
        ))
        .mount(&server)
        .await;

    let error = client(&server)
        .pull_request_diff(&pull_request(), 10)
        .await
        .expect_err("a 401 is not a diff");

    assert!(error.is_fatal(), "{error}");
    assert!(!error.is_retryable(), "{error}");
}

#[tokio::test]
async fn a_refused_anchor_is_survivable_so_the_rest_of_the_review_lands() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_string(r#"{"errors":[{"message":"invalid anchor line"}]}"#),
        )
        .mount(&server)
        .await;

    let error = client(&server)
        .post_comment(
            &pull_request(),
            &Comment {
                text: "x".into(),
                anchor: None,
                severity: Severity::Normal,
            },
        )
        .await
        .expect_err("a 400 is not a posted comment");

    assert!(
        !error.is_fatal(),
        "one bad anchor must not cost the other comments: {error}"
    );
    assert!(matches!(
        error,
        BitbucketError::Rejected { status: 400, .. }
    ));
}

#[tokio::test]
async fn a_restarting_instance_is_reported_as_worth_asking_again() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503).set_body_string(""))
        .mount(&server)
        .await;

    let error = client(&server)
        .pull_request_diff(&pull_request(), 10)
        .await
        .expect_err("a 503 is not a diff");

    assert!(error.is_retryable(), "{error}");
    assert!(!error.is_fatal(), "{error}");
}

#[tokio::test]
async fn a_host_that_is_not_there_is_a_transport_failure_not_a_refusal() {
    // Port 1 on loopback: nothing listens, and the connection is refused
    // rather than timing out, so this stays fast.
    let error = Client::new("http://127.0.0.1:1", Credentials::Bearer("t".into()))
        .unwrap()
        .pull_request_diff(&pull_request(), 10)
        .await
        .expect_err("nothing is listening");

    assert!(matches!(error, BitbucketError::Transport(_)), "{error}");
    assert!(error.is_retryable(), "{error}");
}

#[tokio::test]
async fn a_two_hundred_that_is_not_a_diff_is_malformed_rather_than_empty() {
    let server = MockServer::start().await;

    // The realistic cause is a reverse proxy or SSO portal answering 200 with
    // a login page. Reading that as "this pull request changed nothing" would
    // let a review pass having reviewed nothing at all.
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>sign in</html>"))
        .mount(&server)
        .await;

    let error = client(&server)
        .pull_request_diff(&pull_request(), 10)
        .await
        .expect_err("a login page is not a diff");

    assert!(matches!(error, BitbucketError::Malformed(_)), "{error}");
}
