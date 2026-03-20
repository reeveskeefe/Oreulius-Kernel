/*!
 * Minimal display mode selection state.
 */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeRequest {
    pub width: u32,
    pub height: u32,
    pub bpp: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeSelection {
    pub width: u32,
    pub height: u32,
    pub bpp: u8,
}

impl ModeSelection {
    pub const fn from_request(req: ModeRequest) -> Self {
        ModeSelection {
            width: req.width,
            height: req.height,
            bpp: req.bpp,
        }
    }
}
