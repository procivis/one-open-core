use time::OffsetDateTime;

pub(crate) fn context_requires_update(
    last_modified: OffsetDateTime,
    cache_refresh_timeout: time::Duration,
    refresh_after: time::Duration,
) -> ContextRequiresUpdate {
    let now = OffsetDateTime::now_utc();

    let diff = now - last_modified;

    if diff <= refresh_after {
        ContextRequiresUpdate::IsRecent
    } else if diff <= cache_refresh_timeout {
        ContextRequiresUpdate::CanBeUpdated
    } else {
        ContextRequiresUpdate::MustBeUpdated
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum ContextRequiresUpdate {
    MustBeUpdated,
    CanBeUpdated,
    IsRecent,
}
