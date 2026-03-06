use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Once;

static STOP_SCAN: AtomicBool = AtomicBool::new(false);
static INSTALL_ONCE: Once = Once::new();

pub fn should_stop() -> bool {
    STOP_SCAN.load(Ordering::Relaxed)
}

pub fn request_stop() {
    STOP_SCAN.store(true, Ordering::Relaxed);
}

pub fn reset() {
    STOP_SCAN.store(false, Ordering::Relaxed);
}

pub fn install_ctrlc_handler() -> Result<(), ctrlc::Error> {
    let mut install_result = Ok(());
    INSTALL_ONCE.call_once(|| {
        install_result = ctrlc::set_handler(|| {
            request_stop();
        });
    });
    install_result
}
