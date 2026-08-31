//! The three regions of a store. Each has a base directory measured from the
//! store root. Server-private: no wire spelling, no parse door.

use super::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Region {
    Notes,
    Log,
    Tasks,
}

impl Region {
    pub(crate) fn base(&self) -> Path {
        let spelled = match self {
            Region::Notes => "/",
            Region::Log => "/.logs",
            Region::Tasks => "/.tasks",
        };
        Path::new(spelled).expect("a region base is a constant path")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_region_base_parses() {
        assert_eq!(Region::Notes.base().to_string(), "/");
        assert_eq!(Region::Log.base().to_string(), "/.logs");
        assert_eq!(Region::Tasks.base().to_string(), "/.tasks");
        assert_eq!(Region::Notes.base().segments().count(), 0);
    }
}
