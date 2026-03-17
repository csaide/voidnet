mod ethtool;
mod ifinfo;

pub use ethtool::get_checksum_offload;
pub use ethtool::get_queue_count;
pub use ifinfo::*;
