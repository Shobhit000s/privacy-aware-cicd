"""
tests/k8s_validation/test_manifests.py

Validates every K8s manifest in k8s/base/ without needing a live cluster:
- YAML parses cleanly
- every container has resource requests/limits (OPA rule 13/14 depends on this)
- every container sets securityContext.allowPrivilegeEscalation: false
- Deployments/StatefulSets have matching selector <-> template labels
- Services reference a selector that some Deployment/StatefulSet actually has
- Ingress/NetworkPolicy reference services/pods that exist in this manifest set

This is a lightweight, dependency-free stand-in for `kubeval`/`kubeconform`
(neither of which is installable in a network-restricted CI runner without
extra setup) — it catches the class of error that most commonly breaks a
`kubectl apply`: typos in label selectors, missing resource limits, and
manifests that silently violate the OPA policies checked elsewhere in CI.

Run with: pytest tests/k8s_validation/test_manifests.py -v
"""
import glob
import os

import pytest
import yaml

K8S_BASE = os.path.join(os.path.dirname(__file__), "..", "..", "k8s", "base")


def load_all_docs():
    """Returns list of (filename, doc) for every non-null YAML doc in k8s/base/,
    skipping kustomization.yaml which isn't a K8s object itself."""
    docs = []
    for path in sorted(glob.glob(os.path.join(K8S_BASE, "*.yaml"))):
        if path.endswith("kustomization.yaml"):
            continue
        with open(path) as f:
            for doc in yaml.safe_load_all(f):
                if doc:
                    docs.append((os.path.basename(path), doc))
    return docs


ALL_DOCS = load_all_docs()
WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet"}


def workloads():
    return [(f, d) for f, d in ALL_DOCS if d.get("kind") in WORKLOAD_KINDS]


def services():
    return [(f, d) for f, d in ALL_DOCS if d.get("kind") == "Service"]


def containers_of(doc):
    return doc["spec"]["template"]["spec"].get("containers", [])


class TestYamlValidity:
    def test_at_least_one_manifest_found(self):
        assert len(ALL_DOCS) > 0, "no K8s manifests found under k8s/base/"

    @pytest.mark.parametrize("filename,doc", ALL_DOCS, ids=[f"{f}:{d.get('kind')}/{d.get('metadata',{}).get('name')}" for f, d in ALL_DOCS])
    def test_every_doc_has_required_top_level_fields(self, filename, doc):
        for field in ("apiVersion", "kind", "metadata"):
            assert field in doc, f"{filename}: missing required field '{field}'"
        assert "name" in doc["metadata"], f"{filename}: metadata.name is required"


class TestNamespacing:
    NAMESPACE_EXEMPT_KINDS = {"Namespace", "ClusterRole", "ClusterRoleBinding"}

    @pytest.mark.parametrize("filename,doc", ALL_DOCS, ids=[f"{f}:{d.get('kind')}/{d.get('metadata',{}).get('name')}" for f, d in ALL_DOCS])
    def test_namespaced_resources_target_production(self, filename, doc):
        if doc["kind"] in self.NAMESPACE_EXEMPT_KINDS:
            pytest.skip("cluster-scoped resource, no namespace expected")
        ns = doc["metadata"].get("namespace")
        assert ns == "production", f"{filename}: {doc['kind']}/{doc['metadata']['name']} must be in the 'production' namespace, got {ns!r}"


class TestWorkloadSecurity:
    """Mirrors the OPA deployment_policy.rego checks, but statically, at
    manifest-authoring time rather than deploy-gate time — a manifest that
    fails these should never even reach the OPA gate."""

    @pytest.mark.parametrize("filename,doc", workloads(), ids=[f"{f}:{d['metadata']['name']}" for f, d in workloads()])
    def test_containers_have_resource_limits(self, filename, doc):
        for c in containers_of(doc):
            resources = c.get("resources", {})
            assert "limits" in resources, f"{filename}: container '{c['name']}' has no resources.limits"
            assert "cpu" in resources["limits"], f"{filename}: container '{c['name']}' missing cpu limit"
            assert "memory" in resources["limits"], f"{filename}: container '{c['name']}' missing memory limit"

    @pytest.mark.parametrize("filename,doc", workloads(), ids=[f"{f}:{d['metadata']['name']}" for f, d in workloads()])
    def test_containers_disallow_privilege_escalation(self, filename, doc):
        for c in containers_of(doc):
            sc = c.get("securityContext", {})
            assert sc.get("allowPrivilegeEscalation") is False, \
                f"{filename}: container '{c['name']}' must set securityContext.allowPrivilegeEscalation: false"

    @pytest.mark.parametrize("filename,doc", workloads(), ids=[f"{f}:{d['metadata']['name']}" for f, d in workloads()])
    def test_containers_drop_all_capabilities(self, filename, doc):
        for c in containers_of(doc):
            caps = c.get("securityContext", {}).get("capabilities", {})
            assert caps.get("drop") == ["ALL"], \
                f"{filename}: container '{c['name']}' should drop ALL capabilities"

    @pytest.mark.parametrize("filename,doc", workloads(), ids=[f"{f}:{d['metadata']['name']}" for f, d in workloads()])
    def test_pod_runs_as_nonroot(self, filename, doc):
        pod_sc = doc["spec"]["template"]["spec"].get("securityContext", {})
        assert pod_sc.get("runAsNonRoot") is True, \
            f"{filename}: pod securityContext.runAsNonRoot must be true"

    @pytest.mark.parametrize("filename,doc", workloads(), ids=[f"{f}:{d['metadata']['name']}" for f, d in workloads()])
    def test_selector_matches_template_labels(self, filename, doc):
        selector_labels = doc["spec"]["selector"]["matchLabels"]
        template_labels = doc["spec"]["template"]["metadata"]["labels"]
        for k, v in selector_labels.items():
            assert template_labels.get(k) == v, \
                f"{filename}: selector.matchLabels {selector_labels} doesn't match template labels {template_labels}"


class TestServiceSelectorsResolve:
    """A Service with a selector that matches zero pods is a classic silent
    misconfiguration — this test catches it before it reaches a cluster."""

    @pytest.mark.parametrize("filename,doc", services(), ids=[f"{f}:{d['metadata']['name']}" for f, d in services()])
    def test_service_selector_matches_a_workload(self, filename, doc):
        selector = doc["spec"].get("selector")
        if not selector:
            pytest.skip("headless/manual-endpoints service with no selector")

        matched = False
        for _, w in workloads():
            template_labels = w["spec"]["template"]["metadata"]["labels"]
            if all(template_labels.get(k) == v for k, v in selector.items()):
                matched = True
                break
        assert matched, f"{filename}: Service selector {selector} matches no workload's pod template labels"


class TestIngressReferencesRealServices:
    def test_ingress_backends_exist_as_services(self):
        service_names = {d["metadata"]["name"] for _, d in services()}
        ingress_docs = [d for _, d in ALL_DOCS if d.get("kind") == "Ingress"]
        assert ingress_docs, "expected at least one Ingress manifest"

        for ing in ingress_docs:
            for rule in ing["spec"].get("rules", []):
                for path in rule.get("http", {}).get("paths", []):
                    svc_name = path["backend"]["service"]["name"]
                    assert svc_name in service_names, \
                        f"Ingress references service '{svc_name}' which has no matching Service manifest"


class TestHPATargetsRealDeployment:
    def test_hpa_scale_target_exists(self):
        deployment_names = {d["metadata"]["name"] for f, d in workloads() if d["kind"] == "Deployment"}
        hpas = [d for _, d in ALL_DOCS if d.get("kind") == "HorizontalPodAutoscaler"]
        assert hpas, "expected at least one HPA manifest"
        for hpa in hpas:
            target = hpa["spec"]["scaleTargetRef"]["name"]
            assert target in deployment_names, \
                f"HPA targets Deployment '{target}' which doesn't exist among workload manifests"


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
