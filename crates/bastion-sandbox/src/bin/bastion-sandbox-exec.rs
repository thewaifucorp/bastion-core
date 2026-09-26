//! Standalone sandbox helper, for hosts that would rather not forward
//! `__bastion-sandbox` from their own `main`, and for this crate's tests:
//! `bastion-sandbox-exec __bastion-sandbox ...`.

fn main() {
    bastion_sandbox::helper_main(std::env::args_os().skip(1))
}
