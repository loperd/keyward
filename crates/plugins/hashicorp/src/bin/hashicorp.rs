//! The HashiCorp Vault plugin as a program: the same thing, but as a separate
//! process. The library target stays — it is one and the same `impl Plugin`.

fn main() {
    // The keyward base comes from the package's directory: the ledger of
    // issues lies next to the vault.
    keyward_plugin_stdio::adopt_home();

    // The log goes to `stderr`, which the daemon reads. The level is warnings:
    // a plugin's whole `stderr` reaches the daemon's log marked as a
    // warning.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    keyward_plugin_stdio::run(keyward_plugin_hashicorp::HashicorpPlugin::new())
}
