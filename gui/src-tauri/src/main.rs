// No console window in a release build (this matters for the Windows one).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    keyward_gui_lib::run()
}
