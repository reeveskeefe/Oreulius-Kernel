/*!
 * Hardware/software cursor state.
 */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CursorState {
    pub x: i32,
    pub y: i32,
    pub hot_x: i32,
    pub hot_y: i32,
    pub visible: bool,
}

impl CursorState {
    pub const fn new() -> Self {
        CursorState {
            x: 0,
            y: 0,
            hot_x: 0,
            hot_y: 0,
            visible: true,
        }
    }
}

