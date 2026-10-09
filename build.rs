fn main() {
    #[cfg(feature = "gui")]
    slint_build::compile("ui/app.slint").expect("Failed to compile Slint UI specification");
}
