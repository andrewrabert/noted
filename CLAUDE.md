- Noted:
    - Store(NotedBase)
    - Region(RegionBase=`/`)
        - RegionNotePath
    - Region(RegionBase=`/.logs`)
        - RegionNotePath
    - Region(RegionBase=`/.tasks`)
        - RegionNotePath

- Noted:
    - Store(NotedBase: PathBuf, disk root; only Store holds it)
        - roots RegionBase + RegionNotePath onto NotedBase
        - Trash(`/.trash`) - store-owned; never a Region; only `remove` writes it
    - NoteRegion(RegionBase=`/`)
        - Policy(Scope=NotePath, default=`/`, entries keyed by RegionBase + Scope + name)
        - RegionNotePath - region-relative location; what the mint proves; `RegionBase + RegionNotePath` is what Store roots
        - NotePath - scope-relative; the only spelling a user types
        - Hit<NotePath>
        - Trashed(NotePath)
    - LogRegion(RegionBase=`/.logs`)
        - Policy(...)
        - RegionNotePath
        - NotePath
        - Hit<NotePath>
    - TaskRegion(RegionBase=`/.tasks`)
        - Policy(...)
        - RegionNotePath
        - NotePath (- Task - TaskRef -> NotePath entry (`+ .md`), Group - GroupPath; a task's directory)
        - Hit<NotePath>
    - Policy key - NotePath in PolicyFragment.paths; scope-relative; applies uniformly in every region. `.logs`/`.tasks` are server-private, never on the wire

- Frames (all segment lists, no OS meaning):
    - NotePath - measured from Scope inside a Region; may be empty (`/`, the scope itself); identity; spelled with a leading separator, never a trailing one; `/` alone is root
    - RegionNotePath - measured from RegionBase; non-empty; location the mint proves
    - RegionBase - measured from NotedBase; may be empty (`/`); the region's directory
    - Trie key = RegionBase + RegionNotePath spelled with a separator after every segment; built only by the private `key` fn in policy.rs; never a type

- Crossings:
    - NotePath -> RegionNotePath: only in the Policy mint (readable/writeable), only after the lookup says yes
    - OS entry name -> NotePath: only in fs/ (Store listing, platform grep), outbound, via NotePath::new spelled from the walk root, Err skipped; RegionStore then re-mints each one
    - RegionBase + RegionNotePath -> PathBuf: only in Store
    - NotePath never sees RegionBase, Trash, or PathBuf


| Term       | Type                    | Notes                                                                 |
|------------|-------------------------|-----------------------------------------------------------------------|
| Region     | `Region` enum           | `Region::base()` is `/`, `/.logs`, `/.tasks`; a `RegionStore` per region |
| Scope      | `NotePath`              | holder's subtree in every region; default `/`                         |
| Note       | `NotePath`          |                                                                       |
| Log entry  | `NotePath`          | timestamp name, write-once                                            |
| Policy key | `NotePath`              | in `PolicyFragment.paths`; scope-relative; uniform across regions     |
| Hit        | `Hit<NotePath>`     |                                                                       |
| Trashed    | `NotePath`              | the removed note's name                                               |
| Trash      | `.trash/`               | under store root                                                      |
| Store root | `PathBuf`               | `Store` only                                                          |
