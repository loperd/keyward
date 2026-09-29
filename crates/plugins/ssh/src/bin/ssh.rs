//! The ssh plugin as a program: the same thing, but as a separate process.
//!
//! The library target has not gone anywhere — it is one and the same
//! `impl Plugin`. The only difference is who calls: the daemon through the
//! trait, or the `keyward-plugin-stdio` bridge in lines of JSON.

fn main() {
    // The keyward base comes from the package's directory: the daemon starts
    // the plugin with a clean environment, and the agent's sockets have to lie
    // next to the vault rather than in somebody else's home.
    keyward_plugin_stdio::adopt_home();

    // The log goes to `stderr`: the daemon reads it and files it with the
    // plugin's mark. An external plugin has no other way to say anything about
    // itself. The level is warnings: the daemon marks a plugin's whole `stderr`
    // as a warning, and ordinary work must not look like trouble.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    keyward_plugin_stdio::run(keyward_plugin_ssh::SshPlugin::new())
}
