//! Pure classification of a directory entry from its listing data (never opens the file).

pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
pub const FILE_ATTRIBUTE_OFFLINE: u32 = 0x1000;
pub const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x4_0000;
pub const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x40_0000;

const CLOUD_MASK: u32 =
    FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// Junction, symlink or mount point (name-surrogate reparse point): not entered, not counted.
    Link,
    /// Placeholder whose data lives in the cloud: counted as 0 bytes, never opened.
    CloudOnly,
    /// Ordinary directory — including OneDrive folders, whose cloud reparse tag is not a name surrogate.
    Dir,
    File,
}

/// `is_name_surrogate` comes from the entry's reparse tag (std exposes it as `FileType::is_symlink`).
pub fn classify(attributes: u32, is_name_surrogate: bool) -> EntryKind {
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 && is_name_surrogate {
        return EntryKind::Link;
    }
    let is_dir = attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    if !is_dir && is_cloud_only(attributes) {
        return EntryKind::CloudOnly;
    }
    if is_dir {
        EntryKind::Dir
    } else {
        EntryKind::File
    }
}

/// Any of the three cloud attributes means "opening this may trigger a download".
pub fn is_cloud_only(attributes: u32) -> bool {
    attributes & CLOUD_MASK != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARCHIVE: u32 = 0x20;

    #[test]
    fn attrs_each_cloud_attribute_is_not_opened() {
        for a in [
            FILE_ATTRIBUTE_OFFLINE,
            FILE_ATTRIBUTE_RECALL_ON_OPEN,
            FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
        ] {
            assert!(is_cloud_only(a | ARCHIVE), "{a:#x}");
            assert_eq!(classify(a | ARCHIVE, false), EntryKind::CloudOnly);
            // Cloud files also carry a (non-surrogate) reparse point.
            assert_eq!(
                classify(a | FILE_ATTRIBUTE_REPARSE_POINT, false),
                EntryKind::CloudOnly
            );
        }
    }

    #[test]
    fn attrs_cloud_combinations_are_not_opened() {
        let all = FILE_ATTRIBUTE_OFFLINE
            | FILE_ATTRIBUTE_RECALL_ON_OPEN
            | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
        assert_eq!(classify(all, false), EntryKind::CloudOnly);
        assert_eq!(
            classify(
                FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
                false
            ),
            EntryKind::CloudOnly
        );
        assert_eq!(classify(ARCHIVE, false), EntryKind::File);
    }

    #[test]
    fn attrs_name_surrogates_are_links() {
        let junction = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT;
        assert_eq!(classify(junction, true), EntryKind::Link);
        assert_eq!(
            classify(FILE_ATTRIBUTE_REPARSE_POINT, true),
            EntryKind::Link
        );
    }

    #[test]
    fn attrs_onedrive_folder_is_entered() {
        // Cloud-tagged folder (not a name surrogate), possibly with RECALL_ON_DATA_ACCESS.
        let od = FILE_ATTRIBUTE_DIRECTORY
            | FILE_ATTRIBUTE_REPARSE_POINT
            | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
        assert_eq!(classify(od, false), EntryKind::Dir);
    }
}
