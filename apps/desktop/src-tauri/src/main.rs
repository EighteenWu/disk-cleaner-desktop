#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args
        .first()
        .is_some_and(|value| value == "--background-task")
    {
        if let Err(error) = cleandeck_desktop_lib::run_background_cli(&args) {
            eprintln!("background task failed: {error}");
            std::process::exit(2);
        }
        return;
    }
    cleandeck_desktop_lib::run();
}
