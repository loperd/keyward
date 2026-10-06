//! What of a cluster is shown, and how.
//!
//! A fixed set of kinds, each with the few columns a person scans a list by.
//! A secret's data is never fetched: its list is metadata only, and its
//! manifest is not opened at all.

use k8s_openapi::api::{apps, core, networking, rbac};
use kube::api::{Api, DeleteParams, DynamicObject, ListParams, LogParams, Patch, PatchParams};
use kube::core::{ApiResource, PartialObjectMeta};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// The kinds a person can look at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Namespaces,
    Nodes,
    Pods,
    Deployments,
    StatefulSets,
    DaemonSets,
    Services,
    Ingresses,
    ConfigMaps,
    Secrets,
    Events,
    Roles,
    RoleBindings,
    ClusterRoles,
    ClusterRoleBindings,
    NetworkPolicies,
}

impl Kind {
    fn resource(self) -> ApiResource {
        match self {
            Self::Namespaces => ApiResource::erase::<core::v1::Namespace>(&()),
            Self::Nodes => ApiResource::erase::<core::v1::Node>(&()),
            Self::Pods => ApiResource::erase::<core::v1::Pod>(&()),
            Self::Deployments => ApiResource::erase::<apps::v1::Deployment>(&()),
            Self::StatefulSets => ApiResource::erase::<apps::v1::StatefulSet>(&()),
            Self::DaemonSets => ApiResource::erase::<apps::v1::DaemonSet>(&()),
            Self::Services => ApiResource::erase::<core::v1::Service>(&()),
            Self::Ingresses => ApiResource::erase::<networking::v1::Ingress>(&()),
            Self::ConfigMaps => ApiResource::erase::<core::v1::ConfigMap>(&()),
            Self::Secrets => ApiResource::erase::<core::v1::Secret>(&()),
            Self::Events => ApiResource::erase::<core::v1::Event>(&()),
            Self::Roles => ApiResource::erase::<rbac::v1::Role>(&()),
            Self::RoleBindings => ApiResource::erase::<rbac::v1::RoleBinding>(&()),
            Self::ClusterRoles => ApiResource::erase::<rbac::v1::ClusterRole>(&()),
            Self::ClusterRoleBindings => ApiResource::erase::<rbac::v1::ClusterRoleBinding>(&()),
            Self::NetworkPolicies => ApiResource::erase::<networking::v1::NetworkPolicy>(&()),
        }
    }

    fn namespaced(self) -> bool {
        !matches!(self, Self::Namespaces | Self::Nodes | Self::ClusterRoles | Self::ClusterRoleBindings)
    }

    fn api(self, client: &kube::Client, namespace: Option<&str>) -> Api<DynamicObject> {
        let ar = self.resource();
        match namespace.filter(|_| self.namespaced()) {
            Some(ns) => Api::namespaced_with(client.clone(), ns, &ar),
            None => Api::all_with(client.clone(), &ar),
        }
    }
}

/// One row of a list.
#[derive(Debug, Clone, Serialize)]
pub struct Row {
    pub name: String,
    pub namespace: Option<String>,
    /// Seconds since the epoch.
    pub created: Option<i64>,
    /// The kind's own columns, by name.
    pub info: Value,
}

fn created(meta: &kube::api::ObjectMeta) -> Option<i64> {
    meta.creation_timestamp.as_ref().map(|t| t.0.as_second())
}

/// What a person scans a list of this kind by.
fn info(kind: Kind, o: &Value) -> Value {
    let n = |p: &str| o.pointer(p).and_then(Value::as_i64).unwrap_or(0);
    let s = |p: &str| o.pointer(p).and_then(Value::as_str).map(str::to_string);
    match kind {
        Kind::Pods => {
            let statuses = o.pointer("/status/containerStatuses").and_then(Value::as_array).cloned().unwrap_or_default();
            let ready = statuses.iter().filter(|c| c["ready"] == true).count();
            let restarts: i64 = statuses.iter().map(|c| c["restartCount"].as_i64().unwrap_or(0)).sum();
            let containers: Vec<String> = o
                .pointer("/spec/containers")
                .and_then(Value::as_array)
                .map(|cs| cs.iter().filter_map(|c| c["name"].as_str().map(str::to_string)).collect())
                .unwrap_or_default();
            json!({
                "phase": s("/status/phase"),
                "ready": ready,
                "total": containers.len(),
                "restarts": restarts,
                "node": s("/spec/nodeName"),
                "containers": containers,
            })
        }
        Kind::Deployments | Kind::StatefulSets => json!({ "ready": n("/status/readyReplicas"), "total": n("/spec/replicas") }),
        Kind::DaemonSets => json!({ "ready": n("/status/numberReady"), "total": n("/status/desiredNumberScheduled") }),
        Kind::Services => json!({
            "type": s("/spec/type"),
            "cluster_ip": s("/spec/clusterIP"),
            "ports": o.pointer("/spec/ports").and_then(Value::as_array).map(|ps| ps.iter()
                .map(|p| format!("{}/{}", p["port"], p["protocol"].as_str().unwrap_or("TCP"))).collect::<Vec<_>>()),
        }),
        Kind::Ingresses => json!({
            "hosts": o.pointer("/spec/rules").and_then(Value::as_array).map(|rs| rs.iter()
                .filter_map(|r| r["host"].as_str().map(str::to_string)).collect::<Vec<_>>()),
        }),
        Kind::Nodes => {
            let ready = o
                .pointer("/status/conditions")
                .and_then(Value::as_array)
                .and_then(|cs| cs.iter().find(|c| c["type"] == "Ready"))
                .map(|c| c["status"] == "True");
            json!({ "ready": ready, "version": s("/status/nodeInfo/kubeletVersion") })
        }
        Kind::Namespaces => json!({ "phase": s("/status/phase") }),
        Kind::ConfigMaps => json!({ "keys": o.get("data").and_then(Value::as_object).map(|d| d.len()).unwrap_or(0) }),
        Kind::Events => json!({
            "type": s("/type"),
            "reason": s("/reason"),
            "message": s("/message"),
            "object": format!("{}/{}", o.pointer("/involvedObject/kind").and_then(Value::as_str).unwrap_or(""),
                o.pointer("/involvedObject/name").and_then(Value::as_str).unwrap_or("")),
            "count": n("/count"),
            "last": s("/lastTimestamp").or_else(|| s("/eventTime")),
        }),
        Kind::Roles | Kind::ClusterRoles => json!({ "rules": o.get("rules").and_then(Value::as_array).map(|r| r.len()).unwrap_or(0) }),
        Kind::RoleBindings | Kind::ClusterRoleBindings => json!({
            "role": format!("{}/{}", s("/roleRef/kind").unwrap_or_default(), s("/roleRef/name").unwrap_or_default()),
            "subjects": o.get("subjects").and_then(Value::as_array).map(|ss| ss.iter()
                .map(|x| format!("{}:{}", x["kind"].as_str().unwrap_or(""), x["name"].as_str().unwrap_or(""))).collect::<Vec<_>>()),
        }),
        Kind::NetworkPolicies => json!({
            "selector": o.pointer("/spec/podSelector/matchLabels").cloned(),
            "types": o.pointer("/spec/policyTypes").cloned(),
        }),
        Kind::Secrets => Value::Null,
    }
}

/// A kube error in the words a person reads.
pub fn api_error(kind: &str, e: kube::Error) -> anyhow::Error {
    match &e {
        kube::Error::Api(status) if status.code == 403 => keyward_core::fault!("err.kubeForbidden", "kind" => kind),
        kube::Error::Api(status) if status.code == 401 => {
            tracing::warn!(kind, reason = %status.message, "the cluster refused the kubeconfig's credentials");
            keyward_core::fault!("err.kubeUnauthorized")
        }
        kube::Error::Api(status) if status.code == 404 => keyward_core::fault!("err.kubeNotFound", "kind" => kind),
        kube::Error::Api(status) => keyward_core::fault!("err.kubeApi", "reason" => status.message.as_str()),
        other => keyward_core::fault!("err.kubeUnreachable", "reason" => other.to_string()),
    }
}

fn kind_name(kind: Kind) -> String {
    serde_json::to_value(kind).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

/// A list of one kind, in one namespace or all of them.
pub async fn list(client: &kube::Client, kind: Kind, namespace: Option<&str>) -> anyhow::Result<Vec<Row>> {
    let api = kind.api(client, namespace);
    let name = kind_name(kind);
    if kind == Kind::Secrets {
        // Metadata alone: a secret's data does not come into this process.
        let list = api.list_metadata(&ListParams::default()).await.map_err(|e| api_error(&name, e))?;
        return Ok(list
            .items
            .into_iter()
            .map(|o: PartialObjectMeta<DynamicObject>| Row {
                name: o.metadata.name.clone().unwrap_or_default(),
                namespace: o.metadata.namespace.clone(),
                created: created(&o.metadata),
                info: Value::Null,
            })
            .collect());
    }
    let list = api.list(&ListParams::default()).await.map_err(|e| api_error(&name, e))?;
    Ok(list
        .items
        .into_iter()
        .map(|o| {
            let whole = serde_json::to_value(&o).unwrap_or(Value::Null);
            Row {
                name: o.metadata.name.clone().unwrap_or_default(),
                namespace: o.metadata.namespace.clone(),
                created: created(&o.metadata),
                info: info(kind, &whole),
            }
        })
        .collect())
}

/// One object's manifest as YAML, without the server's bookkeeping.
pub async fn manifest(client: &kube::Client, kind: Kind, namespace: Option<&str>, name: &str) -> anyhow::Result<String> {
    if kind == Kind::Secrets {
        anyhow::bail!(keyward_core::fault!("err.kubeSecretNotShown"));
    }
    let kn = kind_name(kind);
    let mut o = kind.api(client, namespace).get(name).await.map_err(|e| api_error(&kn, e))?;
    o.metadata.managed_fields = None;
    let ar = kind.resource();
    o.types = Some(kube::api::TypeMeta { api_version: ar.api_version.clone(), kind: ar.kind.clone() });
    serde_saphyr::to_string(&o).map_err(|e| anyhow::anyhow!("the manifest will not turn into YAML: {e}"))
}

/// The field manager keyward's changes are made under, the way `kubectl`
/// makes its own under its name.
const MANAGER: &str = "keyward";

/// Which of the known kinds a manifest is, by its `apiVersion` and `kind`.
fn kind_of(object: &DynamicObject) -> anyhow::Result<Kind> {
    let types = object.types.as_ref().ok_or_else(|| keyward_core::fault!("err.kubeManifestNoKind"))?;
    ALL.iter()
        .copied()
        .find(|k| {
            let ar = k.resource();
            ar.api_version == types.api_version && ar.kind == types.kind
        })
        .ok_or_else(|| keyward_core::fault!("err.kubeKindNotSupported", "kind" => types.kind.as_str()))
}

const ALL: &[Kind] = &[
    Kind::Namespaces,
    Kind::Nodes,
    Kind::Pods,
    Kind::Deployments,
    Kind::StatefulSets,
    Kind::DaemonSets,
    Kind::Services,
    Kind::Ingresses,
    Kind::ConfigMaps,
    Kind::Secrets,
    Kind::Events,
    Kind::Roles,
    Kind::RoleBindings,
    Kind::ClusterRoles,
    Kind::ClusterRoleBindings,
    Kind::NetworkPolicies,
];

/// What an apply did, or would do: the object as the server has it after.
#[derive(Debug, Serialize)]
pub struct Applied {
    pub kind: Kind,
    pub namespace: Option<String>,
    pub name: String,
    /// The object after the change, without the server's bookkeeping.
    pub yaml: String,
    /// The object before it, the same way; `None` when it is new.
    pub before: Option<String>,
    pub dry_run: bool,
}

fn tidy(mut o: DynamicObject, kind: Kind) -> anyhow::Result<String> {
    o.metadata.managed_fields = None;
    let ar = kind.resource();
    o.types = Some(kube::api::TypeMeta { api_version: ar.api_version.clone(), kind: ar.kind.clone() });
    serde_saphyr::to_string(&o).map_err(|e| anyhow::anyhow!("the manifest will not turn into YAML: {e}"))
}

/// Applies a manifest, server side, as keyward's own change. With `dry_run`
/// the server checks and computes it and changes nothing: that is what the
/// person sees before they apply for real.
pub async fn apply(client: &kube::Client, yaml: &str, namespace: Option<&str>, dry_run: bool) -> anyhow::Result<Applied> {
    let value: Value = serde_saphyr::from_str(yaml).map_err(|e| keyward_core::fault!("err.kubeManifestUnreadable", "reason" => e.to_string()))?;
    let object: DynamicObject = serde_json::from_value(value.clone()).map_err(|e| keyward_core::fault!("err.kubeManifestUnreadable", "reason" => e.to_string()))?;
    let kind = kind_of(&object)?;
    if kind == Kind::Secrets || kind == Kind::Events {
        anyhow::bail!(keyward_core::fault!("err.kubeKindNotSupported", "kind" => object.types.as_ref().map(|t| t.kind.as_str()).unwrap_or("?")));
    }
    let name = object.metadata.name.clone().ok_or_else(|| keyward_core::fault!("err.kubeManifestNoName"))?;
    let ns = if kind.namespaced() { object.metadata.namespace.clone().or(namespace.map(str::to_string)) } else { None };
    if kind.namespaced() && ns.is_none() {
        anyhow::bail!(keyward_core::fault!("err.kubeManifestNoNamespace"));
    }
    let api = kind.api(client, ns.as_deref());
    let kn = kind_name(kind);
    let before = match api.get_opt(&name).await.map_err(|e| api_error(&kn, e))? {
        Some(o) => Some(tidy(o, kind)?),
        None => None,
    };
    let mut params = PatchParams::apply(MANAGER).force();
    params.dry_run = dry_run;
    let after = api.patch(&name, &params, &Patch::Apply(&value)).await.map_err(|e| api_error(&kn, e))?;
    Ok(Applied { kind, namespace: ns, name, yaml: tidy(after, kind)?, before, dry_run })
}

/// Deletes an object. The window asks the person first, in its danger zone.
pub async fn delete(client: &kube::Client, kind: Kind, namespace: Option<&str>, name: &str) -> anyhow::Result<()> {
    if matches!(kind, Kind::Events | Kind::Nodes) {
        anyhow::bail!(keyward_core::fault!("err.kubeKindNotSupported", "kind" => kind_name(kind)));
    }
    let kn = kind_name(kind);
    // The answer is the object on its way out or a Status, depending on the
    // kind and the moment; only whether it succeeded matters, so the body is
    // not read as either.
    let api = kind.api(client, namespace);
    let request = kube::core::Request::new(api.resource_url())
        .delete(name, &DeleteParams::default())
        .map_err(|e| anyhow::anyhow!("the delete request will not build: {e}"))?;
    client.request_text(request).await.map_err(|e| api_error(&kn, e))?;
    Ok(())
}

/// Sets how many replicas a Deployment or a StatefulSet runs.
pub async fn scale(client: &kube::Client, kind: Kind, namespace: &str, name: &str, replicas: i32) -> anyhow::Result<()> {
    if !matches!(kind, Kind::Deployments | Kind::StatefulSets) || !(0..=1000).contains(&replicas) {
        anyhow::bail!(keyward_core::fault!("err.kubeBadScale"));
    }
    let kn = kind_name(kind);
    let patch = serde_json::json!({ "spec": { "replicas": replicas } });
    kind.api(client, Some(namespace))
        .patch(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .map_err(|e| api_error(&kn, e))?;
    Ok(())
}

/// Restarts a workload's pods one by one, the way `kubectl rollout restart`
/// does: a new annotation on the pod template.
pub async fn restart(client: &kube::Client, kind: Kind, namespace: &str, name: &str) -> anyhow::Result<()> {
    if !matches!(kind, Kind::Deployments | Kind::StatefulSets | Kind::DaemonSets) {
        anyhow::bail!(keyward_core::fault!("err.kubeKindNotSupported", "kind" => kind_name(kind)));
    }
    let at = jiff::Timestamp::now().to_string();
    let patch = serde_json::json!({ "spec": { "template": { "metadata": { "annotations": { "kubectl.kubernetes.io/restartedAt": at } } } } });
    let kn = kind_name(kind);
    kind.api(client, Some(namespace))
        .patch(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .map_err(|e| api_error(&kn, e))?;
    Ok(())
}

/// The tail of a pod's log. Capped: a log is for reading, not for copying off.
pub async fn logs(client: &kube::Client, namespace: &str, pod: &str, container: Option<String>, tail: i64) -> anyhow::Result<String> {
    let api: Api<core::v1::Pod> = Api::namespaced(client.clone(), namespace);
    let params = LogParams { container, tail_lines: Some(tail.clamp(1, 5000)), limit_bytes: Some(1 << 20), ..LogParams::default() };
    api.logs(pod, &params).await.map_err(|e| api_error("pods", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pod_is_summed_up_by_readiness_restarts_and_node() {
        let pod = json!({
            "spec": { "nodeName": "n1", "containers": [{ "name": "app" }, { "name": "side" }] },
            "status": { "phase": "Running", "containerStatuses": [
                { "ready": true, "restartCount": 2 }, { "ready": false, "restartCount": 1 }
            ] }
        });
        let got = info(Kind::Pods, &pod);
        assert_eq!(got["ready"], 1);
        assert_eq!(got["total"], 2);
        assert_eq!(got["restarts"], 3);
        assert_eq!(got["node"], "n1");
        assert_eq!(got["containers"], json!(["app", "side"]));
    }

    #[test]
    fn kinds_travel_as_the_page_writes_them() {
        assert_eq!(kind_name(Kind::ClusterRoleBindings), "cluster_role_bindings");
        assert_eq!(serde_json::from_value::<Kind>(json!("network_policies")).unwrap(), Kind::NetworkPolicies);
        assert!(!Kind::Nodes.namespaced());
        assert!(Kind::NetworkPolicies.namespaced());
    }
}
