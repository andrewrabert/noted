use crate::path::RelPath;

#[derive(Clone)]
pub(crate) struct Areas {
    pub(crate) log: RelPath,
    pub(crate) tasks: RelPath,
    pub(crate) trash: RelPath,
}

impl Areas {
    pub(crate) fn new() -> Areas {
        Areas {
            log: RelPath::trusted("Log"),
            tasks: RelPath::trusted("Tasks"),
            trash: RelPath::trusted(".trash"),
        }
    }
}
