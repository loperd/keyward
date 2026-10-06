//! The Kubernetes plugin as a program: the same `impl Plugin`, called through
//! the `keyward-plugin-stdio` bridge rather than the trait.

fn main() {
    keyward_plugin_stdio::adopt_home();

    // The log goes to `stderr`, which the daemon files under the plugin's
    // name. Warnings and worse: the daemon marks the whole of it as a warning.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,keyward_plugin_kube=info")),
        )
        .init();

    keyward_plugin_stdio::run(keyward_plugin_kube::KubePlugin::new())
}
