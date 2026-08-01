use chrono::Local;

use crate::areas::Areas;
use crate::caller::Caller;
use crate::error::Result;
use crate::note::{LogFront, LogNote, Note as _};
use crate::store::Store;
use crate::types::{LogBody, Timestamp};

#[derive(Clone)]
pub(super) struct Log {
    store: Store,
    areas: Areas,
    caller: Caller,
}

impl Log {
    pub(super) fn new(store: Store, areas: Areas, caller: Caller) -> Log {
        Log {
            store,
            areas,
            caller,
        }
    }

    pub(super) fn note(&self, body: &LogBody) -> Result<LogNote> {
        let now = Local::now();
        let front = LogFront {
            created: Timestamp::from_local(now),
            cwd: std::env::current_dir()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            host: hostname::get()
                .map(|h| h.to_string_lossy().into_owned())
                .unwrap_or_default(),
            source: self.caller.source().cloned(),
        };

        let dir = self
            .areas
            .log
            .joined(&format!("{}/{}", now.format("%Y"), now.format("%m")));
        let stamp = now.format("%Y-%m-%dT%H-%M-%S.%6f").to_string();
        let path = self.store.unique(&dir.joined(&format!("{stamp}.md")), "-");

        let entry = LogNote::new(path, front, body.as_str());
        self.store.write(entry.path(), &entry.to_bytes()?)?;
        Ok(entry)
    }
}
