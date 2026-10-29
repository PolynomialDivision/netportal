//! The users API client against an in-process fake Authentik (INVENTORY 8.1): paging, the
//! completeness checks and every failure mode. A failed read must never yield a directory.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{FakeIdp, TOKEN, user};
use netportal_offboard::directory::{DirectoryError, MAX_PAGE_BYTES, UsersApi};
use serde_json::{Value, json};

fn people(n: usize) -> Vec<Value> {
    (0..n).map(|i| user(&format!("u{i:02}"), i % 3 != 2, &["residents"])).collect()
}

#[tokio::test]
async fn test_all_pages_are_read() {
    let idp = FakeIdp::start(people(7)).await;
    idp.with(|s| s.page_size = 3);
    let dir = idp.client().read().await.expect("directory");
    assert_eq!(dir.len(), 7);
    assert!(dir.contains("u06"));
    let requests = idp.requests();
    let pages: Vec<String> = requests.iter().map(|(q, _)| q.get("page").cloned().unwrap_or_default()).collect();
    assert_eq!(pages, ["1", "2", "3"]);
    for (query, authorized) in &requests {
        assert!(authorized);
        assert_eq!(query.get("include_groups").map(String::as_str), Some("true"));
        assert_eq!(query.get("page_size").map(String::as_str), Some("100"));
    }
}

#[tokio::test]
async fn test_inactive_users_and_groups_are_read() {
    let idp = FakeIdp::start(vec![
        user("a", true, &["residents", "it-admins"]),
        user("x", false, &["residents"]),
        user("n", true, &[]),
    ])
    .await;
    let dir = idp.client().read().await.expect("directory");
    let users: Vec<_> = dir.users().map(|u| (u.uid.as_str(), u.active, u.groups.len())).collect();
    assert_eq!(users, [("a", true, 2), ("n", true, 0), ("x", false, 1)]);
}

#[tokio::test]
async fn test_an_empty_directory_reads_as_empty() {
    // the refusal is the round's guard (offboarding::check_guards), not the reader's
    let idp = FakeIdp::start(vec![]).await;
    assert!(idp.client().read().await.expect("directory").is_empty());
}

async fn read_err(idp: &FakeIdp) -> DirectoryError {
    match idp.client().read().await {
        Ok(dir) => panic!("read {} users, expected an error", dir.len()),
        Err(e) => {
            assert!(!e.to_string().contains(TOKEN), "the token in {e}");
            e
        }
    }
}

#[tokio::test]
async fn test_api_failure_fails_the_read() {
    let idp = FakeIdp::start(people(3)).await;
    idp.with(|s| s.fail = Some(500));
    assert!(matches!(read_err(&idp).await, DirectoryError::Status { page: 1, status: 500 }));
}

#[tokio::test]
async fn test_wrong_token_fails_the_read() {
    let idp = FakeIdp::start(people(3)).await;
    let e = idp.client_with("not-the-reader-token", Duration::from_secs(5)).read().await.expect_err("error");
    assert!(matches!(e, DirectoryError::Status { status: 403, .. }), "{e}");
    assert!(!e.to_string().contains("not-the-reader-token"));
}

#[tokio::test]
async fn test_unreachable_api_fails_the_read() {
    let api = UsersApi::new(
        "http://127.0.0.1:9/api/v3",
        netportal_core::config::Secret::new(TOKEN.into()),
        Duration::from_secs(5),
    )
    .expect("client");
    let e = api.read().await.expect_err("error");
    assert!(matches!(e, DirectoryError::Http { page: 1, .. }), "{e}");
}

#[tokio::test]
async fn test_a_slow_api_times_out() {
    let idp = FakeIdp::start(people(3)).await;
    idp.with(|s| s.delay = Some(Duration::from_secs(3)));
    let e = idp.client_with(TOKEN, Duration::from_millis(300)).read().await.expect_err("error");
    assert!(matches!(e, DirectoryError::Http { .. }), "{e}");
}

#[tokio::test]
async fn test_a_later_page_failing_fails_the_read() {
    let idp = FakeIdp::start(people(5)).await;
    idp.with(|s| {
        s.page_size = 2;
        s.tweak = Some(Arc::new(|page, body| {
            if page == 2 {
                *body = json!({"detail": "boom"});
            }
        }));
    });
    assert!(matches!(read_err(&idp).await, DirectoryError::Format { page: 2, .. }));
}

#[tokio::test]
async fn test_not_json_fails_the_read() {
    let idp = FakeIdp::start(people(1)).await;
    idp.with(|s| s.raw = Some("<html>login</html>".into()));
    assert!(matches!(read_err(&idp).await, DirectoryError::Format { page: 1, .. }));
    idp.with(|s| {
        s.raw = None;
        s.content_type = Some("text/html");
    });
    assert!(matches!(read_err(&idp).await, DirectoryError::Format { page: 1, .. }));
}

#[tokio::test]
async fn test_a_redirect_is_not_followed() {
    let idp = FakeIdp::start(people(1)).await;
    let api = UsersApi::new(
        &format!("{}/redirect", idp.api),
        netportal_core::config::Secret::new(TOKEN.into()),
        Duration::from_secs(5),
    )
    .expect("client");
    assert!(matches!(api.read().await, Err(DirectoryError::Status { status: 302, .. })));
}

#[tokio::test]
async fn test_a_huge_answer_is_refused() {
    let idp = FakeIdp::start(people(1)).await;
    idp.with(|s| s.raw = Some(format!("{{\"x\": \"{}\"}}", "a".repeat(MAX_PAGE_BYTES))));
    assert!(matches!(read_err(&idp).await, DirectoryError::Format { page: 1, .. }));
}

#[tokio::test]
async fn test_the_count_must_stay_the_same() {
    // someone created while the pages are read: the later page reports another total
    let idp = FakeIdp::start(people(5)).await;
    idp.with(|s| {
        s.page_size = 2;
        s.tweak = Some(Arc::new(|page, body| {
            if page == 3 {
                body["pagination"]["count"] = json!(6);
            }
        }));
    });
    assert!(matches!(read_err(&idp).await, DirectoryError::Changed { page: 3, seen: 6, first: 5 }));
}

#[tokio::test]
async fn test_a_skipped_page_fails_the_read() {
    let idp = FakeIdp::start(people(5)).await;
    idp.with(|s| {
        s.page_size = 2;
        s.tweak = Some(Arc::new(|page, body| {
            if page == 1 {
                body["pagination"]["next"] = json!(3);
            }
        }));
    });
    assert!(matches!(read_err(&idp).await, DirectoryError::Format { page: 1, .. }));
}

#[tokio::test]
async fn test_a_page_cut_short_fails_the_read() {
    // the last page lacks a user the count promises
    let idp = FakeIdp::start(people(5)).await;
    idp.with(|s| {
        s.page_size = 2;
        s.tweak = Some(Arc::new(|page, body| {
            if page == 3 {
                body["results"] = json!([]);
            }
        }));
    });
    assert!(matches!(read_err(&idp).await, DirectoryError::Incomplete { read: 4, count: 5 }));
}

#[tokio::test]
async fn test_an_empty_page_before_the_last_fails_the_read() {
    let idp = FakeIdp::start(people(5)).await;
    idp.with(|s| {
        s.page_size = 2;
        s.tweak = Some(Arc::new(|page, body| {
            if page == 2 {
                body["results"] = json!([]);
            }
        }));
    });
    assert!(matches!(read_err(&idp).await, DirectoryError::Format { page: 2, .. }));
}

#[tokio::test]
async fn test_a_user_on_two_pages_fails_the_read() {
    // someone deleted while the pages are read: a user shifts onto the next page again
    let idp = FakeIdp::start(people(5)).await;
    idp.with(|s| {
        s.page_size = 2;
        s.tweak = Some(Arc::new(|page, body| {
            if page == 2 {
                body["results"][0]["uid"] = json!("u01");
            }
        }));
    });
    assert!(matches!(read_err(&idp).await, DirectoryError::Duplicate { .. }));
}

#[tokio::test]
async fn test_the_page_number_must_match() {
    let idp = FakeIdp::start(people(5)).await;
    idp.with(|s| {
        s.page_size = 2;
        s.tweak = Some(Arc::new(|page, body| {
            if page == 2 {
                body["pagination"]["current"] = json!(1);
            }
        }));
    });
    assert!(matches!(read_err(&idp).await, DirectoryError::Format { page: 2, .. }));
}

#[tokio::test]
async fn test_a_last_page_before_total_pages_fails_the_read() {
    let idp = FakeIdp::start(people(5)).await;
    idp.with(|s| {
        s.page_size = 2;
        s.tweak = Some(Arc::new(|page, body| {
            if page == 1 {
                body["pagination"]["next"] = json!(0);
                body["pagination"]["count"] = json!(2);
            }
        }));
    });
    assert!(matches!(read_err(&idp).await, DirectoryError::Format { page: 1, .. }));
}

#[tokio::test]
async fn test_missing_fields_fail_the_read() {
    // without groups_obj (include_groups ignored) everyone would read as "in no group"
    for field in ["groups_obj", "is_active", "uid"] {
        let idp = FakeIdp::start(people(3)).await;
        idp.with(|s| {
            s.tweak = Some(Arc::new(move |_, body| {
                if let Some(user) = body["results"][1].as_object_mut() {
                    user.remove(field);
                }
            }));
        });
        assert!(matches!(read_err(&idp).await, DirectoryError::Format { page: 1, .. }), "{field}");
    }
}
