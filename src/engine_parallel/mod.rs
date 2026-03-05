// Module sketch: parallel compute, thread pool helpers, and DNS workers.
#![allow(unused_imports)]

pub mod compute {
    pub use crate::engines::parallel::*;
}

pub mod dns {
    pub use crate::tasks::dns_lookup::*;
}

pub mod thread_pool {
    pub use crate::engines::thread_pool::*;
}
