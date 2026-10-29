//! The login with the (fake) identity provider (INVENTORY 4.4): the authorization request,
//! refusals, claims, failed and replayed callbacks, where the login goes back to.

mod common;

use axum::http::StatusCode;
use common::{Person, Portal, admin, resident};
use netportal_core::registry;

#[tokio::test]
async fn test_authorization_request() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let mut b = portal.browser();
    let r = b.get("/login").await;
    assert_eq!(r.status, StatusCode::FOUND);
    let location = r.location().expect("location");
    let url = url::Url::parse(&location).expect("url");
    assert_eq!(url.path(), "/application/o/authorize/");
    let q: std::collections::HashMap<String, String> = url.query_pairs().into_owned().collect();
    assert_eq!(q["response_type"], "code");
    assert_eq!(q["client_id"], common::CLIENT_ID);
    assert_eq!(q["redirect_uri"], format!("{}/auth/callback", common::BASE_URL));
    let mut scopes: Vec<&str> = q["scope"].split(' ').collect();
    scopes.sort();
    assert_eq!(scopes, ["email", "openid", "profile"]);
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["code_challenge"].len(), 43);
    assert!(!q["state"].is_empty() && !q["nonce"].is_empty());
    // the secrets of the login are in the encrypted cookie only
    let cookie = b.cookies.values().next().expect("cookie").clone();
    assert!(!cookie.contains(&q["state"]) && !cookie.contains(&q["nonce"]));
}

#[tokio::test]
async fn test_refused_without_policy_or_groups() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let mut no_groups = resident("ng");
    no_groups.omit = vec!["groups"];
    for person in [Person::new(&["vpn-users"], "ref"), no_groups] {
        let mut b = portal.browser();
        let callback = b.login(&person).await;
        assert_eq!(callback.status, StatusCode::FORBIDDEN);
        assert!(callback.text().contains("Your account has no access to the house Wi-Fi."));
        let mut db = portal.db().await;
        assert_eq!(registry::person_state(&mut db, &person.sub).await.expect("state"), None);
        assert!(b.get("/").await.to_login());
    }
}

#[tokio::test]
async fn test_id_token_without_sub_is_refused() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let mut person = resident("nosub");
    person.omit = vec!["sub"];
    let mut b = portal.browser();
    let callback = b.login(&person).await;
    assert_eq!(callback.status, StatusCode::BAD_REQUEST);
    assert!(callback.is_page());
    assert!(b.get("/").await.to_login());
}

#[tokio::test]
async fn test_claim_fallbacks_and_policies() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let mut person = resident("fb");
    person.omit = vec!["preferred_username", "name"];
    portal.browser().login(&person).await;
    let mut db = portal.db().await;
    let people = registry::people(&mut db).await.expect("people");
    assert_eq!(
        (people[&person.sub].username.as_str(), people[&person.sub].display_name.as_str()),
        (person.sub.as_str(), person.sub.as_str())
    );
    for (groups, policy, is_admin) in [
        (vec!["house-admins"], "residents", false),
        (vec!["former-residents"], "guests", false),
        (vec!["it-admins", "former-residents"], "guests", true),
    ] {
        let p = Person::new(&groups, "pol");
        assert_eq!(portal.browser().login(&p).await.status, StatusCode::FOUND);
        let state = registry::person_state(&mut db, &p.sub).await.expect("state").expect("person");
        assert_eq!(state.is_admin, is_admin);
        assert_eq!(registry::person_policy(&mut db, &p.sub).await.expect("policy").as_deref(), Some(policy));
    }
}

#[tokio::test]
async fn test_failed_callbacks_are_400_and_keep_the_session() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    // replayed: 400; the session that had logged in stays (security review L1; Python ended it)
    let mut b = portal.browser();
    portal.idp.log_in_as(&resident("rep"));
    let start = b.get("/login").await.location().expect("location");
    let http = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().expect("client");
    let callback = http.get(&start).send().await.expect("authorize");
    let callback = callback.headers()["location"].to_str().expect("location").replace(common::BASE_URL, "");
    assert_eq!(b.get(&callback).await.status, StatusCode::FOUND);
    assert_eq!(b.get("/").await.status, StatusCode::OK);
    let replay = b.get(&callback).await;
    assert_eq!(replay.status, StatusCode::BAD_REQUEST);
    assert!(replay.text().contains("Something went wrong."));
    assert_eq!(b.get("/").await.status, StatusCode::OK);
    // cancelled at the provider, a wrong state, no state at all
    let mut b = portal.browser();
    let start = b.get("/login").await.location().expect("location");
    let state: String =
        url::Url::parse(&start).expect("url").query_pairs().find(|(k, _)| k == "state").expect("state").1.into_owned();
    assert_eq!(
        b.get(&format!("/auth/callback?error=access_denied&state={state}")).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(b.get("/auth/callback?code=x&state=not-the-state").await.status, StatusCode::BAD_REQUEST);
    assert_eq!(portal.browser().get("/auth/callback").await.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_return_targets_are_local_only() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let person = admin("rt");
    let mut b = portal.browser();
    assert!(b.get("/admin/aps").await.to_login());
    assert!(b.get("/").await.to_login()); // sets no target: the earlier one stays
    assert_eq!(b.login(&person).await.location().as_deref(), Some("/admin/aps"));
    // a path that would be read as another host is never a target
    let mut b = portal.browser();
    assert_eq!(b.get("//evil.example/").await.status, StatusCode::NOT_FOUND);
    assert_eq!(b.login(&person).await.location().as_deref(), Some("/"));
}

#[tokio::test]
async fn test_a_login_clears_offboarded() {
    let admin_url = need_db!();
    let portal = Portal::new(&admin_url).await;
    let person = resident("again");
    portal.browser().login(&person).await;
    let mut db = portal.db().await;
    registry::offboard_person(&mut db, &person.sub).await.expect("offboard");
    db.commit().await.expect("commit");
    assert_eq!(portal.browser().login(&person).await.status, StatusCode::FOUND);
    assert!(registry::person_state(&mut db, &person.sub).await.expect("state").is_some());
}

#[tokio::test]
async fn test_a_foreign_callback_does_not_log_out() {
    // security review 2026-10-29 L1: another site links to /auth/callback?state=x: 400, and the
    // session the browser has stays
    let admin = need_db!();
    let portal = Portal::new(&admin).await;
    let mut b = portal.browser().logged_in(&resident("cb")).await;
    assert_eq!(b.get("/").await.status, StatusCode::OK);
    for query in ["state=bogus&code=x", "error=access_denied&state=bogus", ""] {
        let r = b.get(&format!("/auth/callback?{query}")).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{query}");
        assert!(!r.set_cookies().iter().any(|c| c.removal()), "{query}: the cookie must not be removed");
        assert_eq!(b.get("/").await.status, StatusCode::OK, "{query}: still logged in");
    }
}
