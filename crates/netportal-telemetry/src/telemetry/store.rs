//! The registry reads the telemetry makes (Python: the `registry` functions the telemetry modules
//! call, INVENTORY 9.11), as a trait: the web passes its request's [`Db`] (the impl below
//! delegates to `netportal_core::registry`), the tests an in-memory fake (Python's
//! `tests/test_telemetry_registry.py` `FakeRegistry`). Nothing here writes.

use std::future::Future;

use indexmap::IndexMap;
use netportal_core::Db;
use netportal_core::registry::{
    self, AcctSession, ApDay, AuthEvent, AuthFailure, ConnectionEvent, DeviceDay, DeviceRow, Incident, JobStatus,
    LatestEvent, LatestSession, MacWindow, Person, RegistryError, WindowConflict,
};
use time::{Date, OffsetDateTime};
use uuid::Uuid;

pub type Result<T> = std::result::Result<T, RegistryError>;

/// The registry functions of INVENTORY 9.11 that the dashboard, the history and the admin views
/// read. Implemented for [`Db`]; every method has the semantics of the `registry` function of the
/// same name.
pub trait Store: Send {
    fn device_windows(
        &mut self,
        ids: &[Uuid],
        since: Option<OffsetDateTime>,
        until: Option<OffsetDateTime>,
    ) -> impl Future<Output = Result<IndexMap<Uuid, Vec<MacWindow>>>> + Send;

    fn window_conflicts(
        &mut self,
        ids: &[Uuid],
        since: Option<OffsetDateTime>,
        until: Option<OffsetDateTime>,
    ) -> impl Future<Output = Result<IndexMap<Uuid, Vec<WindowConflict>>>> + Send;

    fn auth_events(
        &mut self,
        device_id: Uuid,
        since: OffsetDateTime,
        until: OffsetDateTime,
        limit: i64,
    ) -> impl Future<Output = Result<Vec<AuthEvent>>> + Send;

    fn auth_failures(
        &mut self,
        since: OffsetDateTime,
        until: Option<OffsetDateTime>,
        limit: i64,
    ) -> impl Future<Output = Result<Vec<AuthFailure>>> + Send;

    fn acct_sessions(
        &mut self,
        device_id: Uuid,
        since: OffsetDateTime,
        until: OffsetDateTime,
        limit: i64,
    ) -> impl Future<Output = Result<Vec<AcctSession>>> + Send;

    fn latest_sessions(
        &mut self,
        ids: &[Uuid],
        per_device: i64,
    ) -> impl Future<Output = Result<IndexMap<Uuid, Vec<LatestSession>>>> + Send;

    fn latest_connection_events(
        &mut self,
        ids: &[Uuid],
        per_device: i64,
        ssid: Option<&str>,
    ) -> impl Future<Output = Result<IndexMap<Uuid, Vec<LatestEvent>>>> + Send;

    fn connection_events(
        &mut self,
        device_id: Uuid,
        since: OffsetDateTime,
        until: OffsetDateTime,
        limit: i64,
    ) -> impl Future<Output = Result<Vec<ConnectionEvent>>> + Send;

    fn device_days(
        &mut self,
        device_id: Uuid,
        since_day: Date,
        until_day: Date,
    ) -> impl Future<Output = Result<Vec<DeviceDay>>> + Send;

    fn ap_days(&mut self, since_day: Date, until_day: Date) -> impl Future<Output = Result<Vec<ApDay>>> + Send;

    fn incidents(
        &mut self,
        since: OffsetDateTime,
        until: Option<OffsetDateTime>,
        kinds: Option<&[&str]>,
    ) -> impl Future<Output = Result<Vec<Incident>>> + Send;

    fn job_status(&mut self) -> impl Future<Output = Result<Vec<JobStatus>>> + Send;

    fn devices(&mut self, include_revoked: bool) -> impl Future<Output = Result<Vec<DeviceRow>>> + Send;

    fn people(&mut self) -> impl Future<Output = Result<IndexMap<String, Person>>> + Send;

    /// End a failed transaction so the next read works (the admin overview's sections).
    fn rollback(&mut self) -> impl Future<Output = Result<()>> + Send;
}

impl Store for Db {
    async fn device_windows(
        &mut self,
        ids: &[Uuid],
        since: Option<OffsetDateTime>,
        until: Option<OffsetDateTime>,
    ) -> Result<IndexMap<Uuid, Vec<MacWindow>>> {
        registry::device_windows(self, ids, since, until).await
    }

    async fn window_conflicts(
        &mut self,
        ids: &[Uuid],
        since: Option<OffsetDateTime>,
        until: Option<OffsetDateTime>,
    ) -> Result<IndexMap<Uuid, Vec<WindowConflict>>> {
        registry::window_conflicts(self, ids, since, until).await
    }

    async fn auth_events(
        &mut self,
        device_id: Uuid,
        since: OffsetDateTime,
        until: OffsetDateTime,
        limit: i64,
    ) -> Result<Vec<AuthEvent>> {
        registry::auth_events(self, device_id, since, until, limit).await
    }

    async fn auth_failures(
        &mut self,
        since: OffsetDateTime,
        until: Option<OffsetDateTime>,
        limit: i64,
    ) -> Result<Vec<AuthFailure>> {
        registry::auth_failures(self, since, until, limit).await
    }

    async fn acct_sessions(
        &mut self,
        device_id: Uuid,
        since: OffsetDateTime,
        until: OffsetDateTime,
        limit: i64,
    ) -> Result<Vec<AcctSession>> {
        registry::acct_sessions(self, device_id, since, until, limit).await
    }

    async fn latest_sessions(&mut self, ids: &[Uuid], per_device: i64) -> Result<IndexMap<Uuid, Vec<LatestSession>>> {
        registry::latest_sessions(self, ids, per_device).await
    }

    async fn latest_connection_events(
        &mut self,
        ids: &[Uuid],
        per_device: i64,
        ssid: Option<&str>,
    ) -> Result<IndexMap<Uuid, Vec<LatestEvent>>> {
        registry::latest_connection_events(self, ids, per_device, ssid).await
    }

    async fn connection_events(
        &mut self,
        device_id: Uuid,
        since: OffsetDateTime,
        until: OffsetDateTime,
        limit: i64,
    ) -> Result<Vec<ConnectionEvent>> {
        registry::connection_events(self, device_id, since, until, limit).await
    }

    async fn device_days(&mut self, device_id: Uuid, since_day: Date, until_day: Date) -> Result<Vec<DeviceDay>> {
        registry::device_days(self, device_id, since_day, until_day).await
    }

    async fn ap_days(&mut self, since_day: Date, until_day: Date) -> Result<Vec<ApDay>> {
        registry::ap_days(self, since_day, until_day, None).await
    }

    async fn incidents(
        &mut self,
        since: OffsetDateTime,
        until: Option<OffsetDateTime>,
        kinds: Option<&[&str]>,
    ) -> Result<Vec<Incident>> {
        registry::incidents(self, since, until, kinds, None).await
    }

    async fn job_status(&mut self) -> Result<Vec<JobStatus>> {
        registry::job_status(self).await
    }

    async fn devices(&mut self, include_revoked: bool) -> Result<Vec<DeviceRow>> {
        registry::devices(self, None, include_revoked).await
    }

    async fn people(&mut self) -> Result<IndexMap<String, Person>> {
        registry::people(self).await
    }

    async fn rollback(&mut self) -> Result<()> {
        Ok(Db::rollback(self).await?)
    }
}
