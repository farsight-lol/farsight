pub mod ring;
pub mod socket;
pub mod tx_metadata;
pub mod umem;

#[macro_export]
macro_rules! cbail {
    ($guard:expr) => {{
        if $guard {
            return Err(std::io::Error::last_os_error());
        }
    }};

    ($guard:expr => $context:expr) => {{
        if $guard {
            return anyhow::Context::context(
                Err(std::io::Error::last_os_error()),
                $context,
            );
        }
    }};
}
