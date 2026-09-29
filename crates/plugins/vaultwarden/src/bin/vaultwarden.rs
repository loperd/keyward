//! The Vaultwarden admin plugin as a program: the same `impl Plugin`, called
//! through the `keyward-plugin-stdio` bridge in lines of JSON.

fn main() {
    keyward_plugin_stdio::adopt_home();
    // The log goes to `stderr`, which the daemon files under the plugin's
    // mark; warnings only, or ordinary work would read as trouble.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();
    keyward_plugin_stdio::run(keyward_plugin_vaultwarden::VaultwardenPlugin::new())
}
