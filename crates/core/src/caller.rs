use crate::path::RelPath;
use crate::types::Source;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Grant {
    Any,
    Within(Vec<RelPath>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy(Grant);

impl Policy {
    pub fn any() -> Policy {
        Policy(Grant::Any)
    }

    pub fn within(folders: Vec<RelPath>) -> Policy {
        Policy(Grant::Within(folders))
    }

    pub fn admits(&self, path: &RelPath) -> bool {
        match &self.0 {
            Grant::Any => true,
            Grant::Within(folders) => folders.iter().any(|folder| path.under(folder)),
        }
    }
}

impl Default for Policy {
    fn default() -> Policy {
        Policy::any()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caller {
    admits: Policy,
    source: Option<Source>,
}

impl Caller {
    pub fn new(admits: Policy, source: Option<Source>) -> Caller {
        Caller { admits, source }
    }

    pub(crate) fn admits(&self, path: &RelPath) -> bool {
        self.admits.admits(path)
    }

    pub(crate) fn source(&self) -> Option<&Source> {
        self.source.as_ref()
    }

    pub(crate) fn with_policy(&self, admits: Policy) -> Caller {
        Caller {
            admits,
            source: self.source.clone(),
        }
    }
}
