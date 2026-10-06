//! The cluster's API reached through the ssh session.
//!
//! The API server usually listens where only the server itself reaches it —
//! `127.0.0.1:6443` on k3s. Every connection the client makes is a
//! `direct-tcpip` channel of the session, opened from the server's side to the
//! address the kubeconfig names, so no port is opened to the world and nothing
//! is copied off the server. TLS runs inside the channel, end to end with the
//! API server, checked against the kubeconfig's authority.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::TokioIo;
use keyward_ssh_client::connect::Guard;
use kube::client::ConfigExt as _;
use russh::client::{Handle, Msg};
use russh::ChannelStream;

use crate::kubeconfig::Chosen;

/// One channel, as a connection hyper can use.
pub struct Pipe(ChannelStream<Msg>);

impl tokio::io::AsyncRead for Pipe {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for Pipe {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl Connection for Pipe {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

/// Opens every connection as a channel of one session.
#[derive(Clone)]
pub struct Tunnel {
    pub handle: Arc<Handle<Guard>>,
}

impl tower::Service<http::Uri> for Tunnel {
    type Response = TokioIo<Pipe>;
    type Error = anyhow::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: http::Uri) -> Self::Future {
        let handle = Arc::clone(&self.handle);
        Box::pin(async move {
            let host = uri.host().ok_or_else(|| anyhow::anyhow!("the API server's address names no host"))?.to_string();
            // An IPv6 address comes bracketed in a URI and bare to ssh.
            let host = host.trim_start_matches('[').trim_end_matches(']').to_string();
            let port = uri.port_u16().unwrap_or(443);
            let channel = handle
                .channel_open_direct_tcpip(host.clone(), u32::from(port), "127.0.0.1", 0)
                .await
                .map_err(|e| keyward_core::fault!("err.kubeTunnelRefused", "address" => format!("{host}:{port}"), "reason" => e.to_string()))?;
            Ok(TokioIo::new(Pipe(channel.into_stream())))
        })
    }
}

/// A client for the chosen context: through the session when there is one,
/// straight to the server otherwise.
pub async fn client(chosen: Chosen, via: Option<Arc<Handle<Guard>>>) -> anyhow::Result<kube::Client> {
    let config = kube::Config::from_custom_kubeconfig(chosen.config, &kube::config::KubeConfigOptions::default())
        .await
        .map_err(|e| keyward_core::fault!("err.kubeConfigUnreadable", "reason" => e.to_string()))?;
    let Some(handle) = via else {
        return kube::Client::try_from(config).map_err(|e| keyward_core::fault!("err.kubeConfigUnreadable", "reason" => e.to_string()));
    };
    let bad = |e: kube::Error| keyward_core::fault!("err.kubeConfigUnreadable", "reason" => e.to_string());
    let https = config.rustls_https_connector_with_connector(Tunnel { handle }).map_err(bad)?;
    let service = tower::ServiceBuilder::new()
        .layer(config.base_uri_layer())
        .layer(config.extra_headers_layer().map_err(bad)?)
        .option_layer(config.auth_layer().map_err(bad)?)
        .map_err(tower::BoxError::from)
        .service(hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build(https));
    Ok(kube::Client::new(service, config.default_namespace))
}
