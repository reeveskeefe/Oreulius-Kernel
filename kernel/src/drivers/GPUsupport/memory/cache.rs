/*!
 * Cache/coherency policy markers.
 */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoherencyModel {
    Unknown,
    Coherent,
    FlushRequired,
}

