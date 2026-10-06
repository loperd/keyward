//! What a new object starts from: a manifest to change before it is applied.
//! Each is checked by a dry run like any other, so a template is only a first
//! draft — nothing here is applied as it stands.

/// `(id, the words for it, the manifest)`.
pub const TEMPLATES: &[(&str, &str, &str)] = &[
    ("deployment", "kube.tpl.deployment", DEPLOYMENT),
    ("service", "kube.tpl.service", SERVICE),
    ("config_map", "kube.tpl.configMap", CONFIG_MAP),
    ("job", "kube.tpl.job", JOB),
    ("role_read", "kube.tpl.roleRead", ROLE_READ),
    ("role_binding", "kube.tpl.roleBinding", ROLE_BINDING),
    ("deny_ingress", "kube.tpl.denyIngress", DENY_INGRESS),
    ("deny_egress", "kube.tpl.denyEgress", DENY_EGRESS),
    ("same_namespace", "kube.tpl.sameNamespace", SAME_NAMESPACE),
    ("allow_dns", "kube.tpl.allowDns", ALLOW_DNS),
];

const DEPLOYMENT: &str = "apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: app
  template:
    metadata:
      labels:
        app: app
    spec:
      containers:
        - name: app
          image: nginx:stable
          ports:
            - containerPort: 80
";

const SERVICE: &str = "apiVersion: v1
kind: Service
metadata:
  name: app
  namespace: default
spec:
  selector:
    app: app
  ports:
    - port: 80
      targetPort: 80
";

const CONFIG_MAP: &str = "apiVersion: v1
kind: ConfigMap
metadata:
  name: settings
  namespace: default
data:
  key: value
";

const JOB: &str = "apiVersion: batch/v1
kind: Job
metadata:
  name: once
  namespace: default
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: once
          image: busybox:stable
          command: [\"sh\", \"-c\", \"echo done\"]
";

const ROLE_READ: &str = "apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: read-only
  namespace: default
rules:
  - apiGroups: [\"\", \"apps\", \"batch\"]
    resources: [\"*\"]
    verbs: [\"get\", \"list\", \"watch\"]
";

const ROLE_BINDING: &str = "apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-only
  namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: read-only
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: User
    name: someone
";

const DENY_INGRESS: &str = "apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-ingress
  namespace: default
spec:
  podSelector: {}
  policyTypes: [Ingress]
";

const DENY_EGRESS: &str = "apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-egress
  namespace: default
spec:
  podSelector: {}
  policyTypes: [Egress]
";

const SAME_NAMESPACE: &str = "apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: same-namespace
  namespace: default
spec:
  podSelector: {}
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector: {}
";

const ALLOW_DNS: &str = "apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: default
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress:
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
";

#[cfg(test)]
mod tests {
    use super::TEMPLATES;

    #[test]
    fn every_template_is_one_object_with_a_kind_and_a_name() {
        for (id, _, yaml) in TEMPLATES {
            let v: serde_json::Value = serde_saphyr::from_str(yaml).unwrap_or_else(|e| panic!("{id}: {e}"));
            assert!(v["kind"].is_string() && v["metadata"]["name"].is_string(), "{id}");
        }
    }
}
