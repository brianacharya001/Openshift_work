---
title: targeted-update-edge-blocking
authors:
  - "@wking"
reviewers:
  - "@bparees"
  - "@dhellmann"
  - "@jan-f"
  - "@jottofar"
  - "@LalatenduMohanty"
  - "@sdodson"
  - "@vrutkovs"
approvers:
  - "@sdodson"
creation-date: 2020-07-07
last-updated: 2021-09-05
status: implementable
---

# Targeted Update Edge Blocking

## Release Signoff Checklist

- [x] Enhancement is `implementable`
- [x] Design details are appropriately documented from clear requirements
- [x] Test plan is defined
- [x] Graduation criteria for dev preview, tech preview, GA
- [ ] User-facing documentation is created in [openshift-docs](https://github.com/openshift/openshift-docs/)

## Summary

This enhancement proposes a mechanism for blocking edges for the subset of clusters considered vulnerable to known issues with a particular update or target release.

## Motivation

When managing the [Cincinnati][cincinnati-spec] update graph [for OpenShift][cincinnati-for-openshift-design], we sometimes discover issues with particular release images or updates between them.
Once an issue is discovered, we [block edges][block-edges] so we no longer recommend risky updates, or updates to risky releases.

Note: as described [in the documentation][support-documentation], supported updates are still supported even if incoming edges are blocked, and Red Hat will eventually provide supported update paths from any supported release to the latest supported release in its z-stream.
And, since [docs#32091][openshift-docs-32091], [that documentation][support-documentation] also points out that updates initiated after the update recommendation has been removed are still supported.

Incoming bugs are evaluated to determine an impact statement based on [a generic template][rhbz-1858026-impact-statement-request].
Some bugs only impact specific platforms, or clusters with other specific features.
For example, rhbz#1858026 [only impacted][rhbz-1858026-impact-statement] clusters with the `None` platform which were created as 4.1 clusters and subsequently updated via 4.2, 4.3, and 4.4 to reach 4.5.
And rhbz#1957584 [only impacted][rhbz-1957584-impact-statement] clusters updating from 4.6 to 4.7 with Routes whose `spec.host` contains no dots or was otherwise an invalid domain name.

In those cases there is currently tension between wanting to protect vulnerable clusters by blocking the edge vs. wanting to avoid inconveniencing clusters which we know are not vulnerable and whose administrators may have been planning on taking the recommended update.
This enhancement aims to reduce that tension.

### Goals

* [Cincinnati graph-data][graph-data] maintainers will have the ability to block edges for a vulnerable subset of clusters.

### Non-Goals

* Exactly scoping the set of blocked clusters to those which would have been impacted by the issue.
    For example, some issues may be races where the impacted cluster set is a random subset of the vulnerable cluster set.
    Any targeting of the blocked edges will reduce the number of blocked clusters which would have not been impacted, and thus reduce the contention between protecting vulnerable clusters and inconveniencing invulnerable clusters, so even overly broad scoping is better than no scoping at all.
* Specifying a particular update service implementation.
    This enhancement floats some ideas, but the details of the chosen approach are up to each update service's maintainers.

## Proposal

### Enhanced graph-data schema for blocking edges

[The existing blocked-edges schema][block-edges] will be extended with the following new properties:

* `url` (optional, [string][json-string]), with a URI documenting the blocking reason.
    For example, this could link to a bug's impact statement or knowledge-base article.
* `reason` (optional, [string][json-string]), with a CamelCase reason suitable for [a `ClusterOperatorStatusCondition` `reason` property][api-reason].
* `message` (optional, [string][json-string]), with a human-oriented message describing the blocking reason, suitable for [a `ClusterOperatorStatusCondition` `message` property][api-message].
* `clusters` (optional, [object][json-object]), defining the subset of clusters for which the block applies.
  If any `clusters` property matches a given cluster, the edge should be blocked for that cluster.
  If `clusters` is unset or empty, the edge is blocked for all clusters.
  * `promql` (optional, [string][json-string]), with a [PromQL][] query describing affected clusters.
    This query will be evaluated on the local cluster, so it has access to data beyond the subset that is [uploaded to Telemetry][uploaded-telemetry].
    The query should return a 0 if the update should be allowed and a 1 if the update should be blocked.

[The schema version][graph-data-schema-version] would also be bumped to 1.1.0, because this is a backwards-compatible change.
Consumers who only understand graph-data schema 1.0.0 would ignore the `clusters` property and block the edge for all clusters.
The alternative of failing open is discussed [here](#failing-open).

### Enhanced Cincinnati JSON representation

[The Cincinnati graph API][cincinnati-api] will be extended with a new top-level `conditionalEdges` property, with an array of conditional edge [objects][json-object] using the following schema:

* `edges` (required, [array][json-array]), with the update edges covered by this entry.
  Each entry is an [object][json-object] with the following schema:
  * `from` (required, [string][json-string]), with the `version` of the starting node.
  * `to` (required, [string][json-string]), with the `version` of the ending node.
* `qualifiers` (optional, [array][json-array], with qualifications around the recommendation.
  Each entry is an [object][json-object] with the following schema:
  * `url` (optional, [string][json-string]), with a URI documenting the issue, as described in [the blocked-edges section](#enhanced-graph-data-schema-for-blocking-edges).
  * `reason` (optional, [string][json-string]), with a CamelCase reason, as described in [the blocked-edges section](#enhanced-graph-data-schema-for-blocking-edges).
  * `message` (optional, [string][json-string]), with a human-oriented message describing the blocking reason, as described in [the blocked-edges section](#enhanced-graph-data-schema-for-blocking-edges).
  * `blockedClusters` (optional, [object][json-object]).
    If any `blockedClusters` property matches a given cluster, the edge is not recommended for that cluster, as described in [the blocked-edges section](#enhanced-graph-data-schema-for-blocking-edges).
    If `blockedClusters` is unset, the edge is blocked for all clusters.
    * `promql` (optional, [string][json-string]), defining the subset of affected clusters, as described in [the blocked-edges section](#enhanced-graph-data-schema-for-blocking-edges).

### Enhanced ClusterVersion representation

[The ClusterVersion `status`][api-cluster-version-status] will be extended with a new `conditionalUpdates` property:

```go
// conditionalUpdates contains the list of updates that may be
// recommended for this cluster if it meets specific required
// conditions. Consumers interested in the set of updates that are
// actually recommended for this cluster should use
// availableUpdates. This list may be empty if no updates are
// recommended, if the update service is unavailable, or if an empty
// or invalid channel has been specified.
// +optional
conditionalUpdates []ConditionalUpdate `json:"conditionalUpdates,omitempty"`
```

The `availableUpdates` documentation will be adjusted to read:

```go
// availableUpdates contains the subset of conditionalUpdates that
// apply to this cluster.  Updates which appear in conditionalUpdates
// but not in availableUpdates may expose this cluster to known
// issues.
```

The new ConditionalUpdate type will have the following schema:

```go
// ConditionalUpdate represents an update which is recommended to some
// clusters on the version the current cluster is reconciling, but which
// may not be recommended for the current cluster.
// +k8s:deepcopy-gen=true
type ConditionalUpdate struct {
	// release is the target of the update.
	// +required
	release Release `json:"release"`

	// blockedClusters represents the subset of clusters for which the conditional update is not recommended.
	// +required
	BlockedClusters []ConditionalUpdateBlocker `json:"blockedClusters"`

	// conditions represents the observations of the conditional update's
	// current status. Known types are:
	// * Recommended, for whether the update is recommended for the current cluster.
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"`
}
```

The new ConditionalUpdateBlocker type will have the following schema:

```go
// ConditionalUpdateBlocker represents a reason and cluster-set for
// blocking a conditional update.
// +k8s:deepcopy-gen=true
type ConditionalUpdateBlocker struct {
	// url contains information about this release. This URL is set by
	// the 'url' metadata property on a release or the metadata returned by
	// the update API and should be displayed as a link in user
	// interfaces. The URL field may not be set for test or nightly
	// releases.
	// +optional
	URL URL `json:"url,omitempty"`

	// reason is the CamelCase reason for the condition's current status.
	// +optional
	Reason string `json:"reason,omitempty"`

	// message provides additional information about the current condition.
	// This is only to be consumed by humans. It may contain Line Feed
	// characters (U+000A), which should be rendered as new lines.
	// +optional
	Message string `json:"message,omitempty"`

	// promQL is a PromQL query describing affected clusters. The query
	// should return a 0 if the update should be allowed and a 1 if the
	// update should be blocked.
	// +optional
	PromQL string `json:"promQL,omitempty"`
}
```

[ClusterVersion's `status.history` entries][api-history] will be extended with the following property:

```go
// overrides records update guards which were overriden to initiate the update.
Overrides string `json:"overrides,omitempty"`
```

### Update service support for the enhanced schema

The following recommendations are geared towards the [openshift/cincinnati][cincinnati].
Maintainers of other update service implementations may or may not be able to apply them to their own implementation.

The graph-builder's graph-data scraper should learn about [the new 1.1.0 schema](#enhanced-graph-data-schema-for-blocking-edges), and include the new properties in its blocker cache.
For each edge declared by a release image (primary metadata), the graph-builder will check the blocker cache for matching blocks.
Edges with no matching blocks are unconditionally recommended, and will be included in `edges`.
Edges with matching blocks are conditionally recommended, and will be included in `conditionalEdges`.

### Cluster-version operator support for the enhanced schema

The cluster-version operator will learn to parse [`conditionalEdges`](#enhanced-cincinnati-json-representation) into [`conditionalUpdates`](#enhanced-clusterversion-representation).
`edges` will continue to go straight into `availableUpdates`.
The operator will log an error if the same target is included in both `edges` and `conditionalEdges`, but will prefer the `conditionalEdges` entry in that case.

Additionally, the operator will continually re-evaluate the blocking conditionals in `conditionalUpdates` and update `conditionalUpdates[].conditions` accordingly.
The timing of the evaluation and fresheness are largely internal details.
The operator can periodically poll, or use edge triggered watches, combinations of watching and polling, etc.

To perform the PromQL request, the operator will FIXME: details about connecting to the local Thanos/Prometheus.

If there are issues evaluating a conditional update, the operator will set the `Unknown` status on the `Recommended` condition.
The operator will grow a new `warning`-level `CannotEvaluateConditionalUpdates` alert that fires if `lastTransitionTime` for any `Recommended=Unknown` condition is over an hour old.

Any `conditionalUpdates` with `Recommended=True` will have its release inserted into `availableUpdates`.

Both `availableUpdates` and `conditionalUpdates` should be sorted in decreasing SemVer order for stability, to avoid unnecessary status churn.

The cluster version operator does not currently gate update acceptance on whether the requested target release is a recommended update.
With this enhancement, the CVO will add non-blocking gates.
Update targets that are not currently recommended, or are not supported at all, will be allowed without any ClusterVersion overrides ([`force`][api-force] or a similar, new property).
But update targets that are not currently recommended will result in entries in [the `overrides` history entries](#enhanced-clusterversion-representation).

### Update client support for the enhanced schema

[The web-console][web-console] and [`oc`][oc] both consume ClusterVersion to present clients with a list of available updates.
With this enhancement, they will both be extended to consume [`conditionalUpdates`](#enhanced-clusterversion-representation).
When listing recommended updates, clients will list the contents of `availableUpdates`.
When listing all supported updates, clients will additionally include entries from `conditionalUpdates` with `Recommended!=True`, and include the `reason` and `message` from the `Recommended` condition alongside the supported-but-not-recommended updates (if this output is too verbose, clients may want to hide it behind an option like `--include-not-recommended`).
Clients may optionally provision for reporting additional condition types, in case new types are added in the future.

The set of supported-but-not-recommended updates is pretty verbose.
The `oc` folks would probably want to hide it behind a flag like `--include-not-recommended`.

Updating to a conditional edge that the cluster does not qualify for may reqire `--allow-not-recommended` or similar client-side gate.

### User Stories

The following user stories will walk users through an example flow around the [authentication operator's leaked connections][rhbz-1941840-impact-statement].

#### Graph-data administrators

The graph-data administrators would create a new file `blocked-edges/4.7.4-auth-connection-leak.yaml` like:

```yaml
to: 4.7.4
from: 4\.6\..*
url: https://bugzilla.redhat.com/show_bug.cgi?id=1941840#c33
reason: AuthOAuthProxyLeakedConnections
message: On clusters with a Proxy configured, the authentication operator may keep many oauth-server connections open, resulting in high memory consumption by the authentication operator and router pods.
clusters:
  promql: max(cluster_proxy_enabled{type=~"https?"})
```

This would join existing entries like `blocked-edges/4.7.4-vsphere-hostnames-changing.yaml`:

```yaml
to: 4.7.4
from: .*
url: https://bugzilla.redhat.com/show_bug.cgi?id=1942207#c3
reason: VSphereNodeNameChanges
message: vSphere clusters leveraging the vSphere cloud provider may lose node names which can have serious impacts on the stability of the control plane and workloads.
clusters:
  promql: |
    cluster_infrastructure_provider{type=~"VSphere|None"}
    or
    0 * cluster_infrastructure_provider
```

and `blocked-edges/4.7.4-vsphere-hw-17-cross-node-networking.yaml`:

```yaml
to: 4.7.4
from: 4\.6\..*
url: https://access.redhat.com/solutions/5896081
reason: VSphereHW14CrossNodeNetworkingError
message: Clusters on vSphere Virtual Hardware Version 14 and later may experience cross-node networking issues.
clusters:
  promql: |
    cluster_infrastructure_provider{type=~"VSphere|None"}
    or
    0 * cluster_infrastructure_provider
```

#### Cincinnati JSON

Update services would consume the above graph-data, and serve graphs with:

```json
{
  "conditionalEdges": [
    ...
    {
      "edges": [
        ...
        {"from": "4.6.23", "to": "4.7.4"},
        ...
      ],
      "qualifiers": [
        {
          "url": "https://bugzilla.redhat.com/show_bug.cgi?id=1941840#c33",
          "reason": "AuthOAuthProxyLeakedConnections",
          "message": "On clusters with a Proxy configured, the authentication operator may keep many oauth-server connections open, resulting in high memory consumption by the authentication operator and router pods."
          "blockedClusters": {
            "promql": "max(cluster_proxy_enabled{type=~\"https?\"})",
          }
        },
        {
          "url": "https://bugzilla.redhat.com/show_bug.cgi?id=1942207#c3",
          "reason": "VSphereNodeNameChanges",
          "message": "vSphere clusters leveraging the vSphere cloud provider may lose node names which can have serious impacts on the stability of the control plane and workloads.",
          "blockedClusters": {
            "promql": "cluster_infrastructure_provider{type=~\"VSphere|None\"}\nor\n0 * cluster_infrastructure_provider"
          }
        },
        {
          "url": "https://access.redhat.com/solutions/5896081",
          "reason": "VSphereHW14CrossNodeNetworkingError",
          "message": "Clusters on vSphere Virtual Hardware Version 14 and later may experience cross-node networking issues.",
          "blockedClusters": {
            "promql": "cluster_infrastructure_provider{type=~\"VSphere|None\"}\nor\n0 * cluster_infrastructure_provider"
          }
        }
      ]
    },
    ...
  ],
  "edges": [...],
  "nodes": [...],
}
```

#### ClusterVersion representation

The CVO on a vSphere HW 14 cluster with a proxy configured would consume the above Cincinnati JSON, and populate ClusterVersion like:

```yaml
...
status:
  availableUpdates:
  - version: 4.6.43
    image: quay.io/openshift-release-dev/ocp-release@sha256:2b8efb25c1c9d7a713ae74b8918457280f9cc0c66d475e78d3676810d568b534
    url: https://access.redhat.com/errata/RHBA-2021:3197
    channels: ...
  - version: 4.6.42
    image: quay.io/openshift-release-dev/ocp-release@sha256:59e2e85f5d1bcb4440765c310b6261387ffc3f16ed55ca0a79012367e15b558b
    url: https://access.redhat.com/errata/RHBA-2021:3008
    channels: ...
  conditionalUpdates:
  ...
  - release:
    - version: 4.7.4
      image: quay.io/openshift-release-dev/ocp-release@sha256:999a6a4bd731075e389ae601b373194c6cb2c7b4dadd1ad06ef607e86476b129
      url: https://access.redhat.com/errata/RHBA-2021:3008
      channels: ...
    blockedClusters:
    - url: https://bugzilla.redhat.com/show_bug.cgi?id=1941840#c33
      reason: AuthOAuthProxyLeakedConnections
      message: On clusters with a Proxy configured, the authentication operator may keep many oauth-server connections open, resulting in high memory consumption by the authentication operator and router pods.
      promql: "max(cluster_proxy_enabled{type=~\"https?\"})"
    - url: https://bugzilla.redhat.com/show_bug.cgi?id=1942207#c3
      reason: VSphereNodeNameChanges
      message: vSphere clusters leveraging the vSphere cloud provider may lose node names which can have serious impacts on the stability of the control plane and workloads.
      promql: |
        cluster_infrastructure_provider{type=~"VSphere|None"}
        or
        0 * cluster_infrastructure_provider
    - url: https://access.redhat.com/solutions/5896081",
      reason: VSphereHW14CrossNodeNetworkingError",
      message: Clusters on vSphere Virtual Hardware Version 14 and later may experience cross-node networking issues.
      promql: |
        cluster_infrastructure_provider{type=~"VSphere|None"}
        or
        0 * cluster_infrastructure_provider
    conditions:
    - lastTransitionTime: 2021-08-28T01:00:00Z
      type: Recommended
      status: False
      reason: MultipleReasons
      message: |
        Clusters on vSphere Virtual Hardware Version 14 and later may experience cross-node networking issues. https://access.redhat.com/solutions/5896081

        vSphere clusters leveraging the vSphere cloud provider may lose node names which can have serious impacts on the stability of the control plane and workloads. https://bugzilla.redhat.com/show_bug.cgi?id=1942207#c3

        On clusters with a Proxy configured, the authentication operator may keep many oauth-server connections open, resulting in high memory consumption by the authentication operator and router pods. https://bugzilla.redhat.com/show_bug.cgi?id=1941840#c33
  ...
```

#### Cluster administrator

The cluster administrator using a client to inspect available updates would see output like:

```console
$ oc adm upgrade
Cluster version is 4.6.23

Upstream: https://api.openshift.com/api/upgrades_info/graph
Channel: stable-4.6 (available channels: candidate-4.6, candidate-4.7, eus-4.6, fast-4.6, fast-4.7, stable-4.6, stable-4.7)

Recommended updates:

  VERSION	IMAGE
  4.6.43	quay.io/openshift-release-dev/ocp-release@sha256:2b8efb25c1c9d7a713ae74b8918457280f9cc0c66d475e78d3676810d568b534
  4.6.42	quay.io/openshift-release-dev/ocp-release@sha256:59e2e85f5d1bcb4440765c310b6261387ffc3f16ed55ca0a79012367e15b558b
  ...other unconditional or conditional for this cluster targets, in decreasing SemVer order...

Supported but not recommended updates:

  Version: 4.7.4
  Image: quay.io/openshift-release-dev/ocp-release@sha256:999a6a4bd731075e389ae601b373194c6cb2c7b4dadd1ad06ef607e86476b129
  Recommended: False
  Reason: MultipleReasons
  Message:
    Clusters on vSphere Virtual Hardware Version 14 and later may experience cross-node networking issues. https://access.redhat.com/solutions/5896081

    vSphere clusters leveraging the vSphere cloud provider may lose node names which can have serious impacts on the stability of the control plane and workloads. https://bugzilla.redhat.com/show_bug.cgi?id=1942207#c3

    On clusters with a Proxy configured, the authentication operator may keep many oauth-server connections open, resulting in high memory consumption by the authentication operator and router pods. https://bugzilla.redhat.com/show_bug.cgi?id=1941840#c33

  Version: 4.6.99-example
  Image: quay.io/openshift-release-dev/ocp-release@...
  Recommended: Unknown
  Reason: PromQLError
  Message: Unable to evaluate PromQL to determine if the cluster is impacted by ExampleReason. https://example.com/ExampleReason

  Version: 4.6.30
  Image: quay.io/openshift-release-dev/ocp-release@sha256:476588ee99a28f39410372175925672e9a37f0cd1272e17ed2454d7f5cafff90
  Recommended: False
  Reason: ThanosDNSUnmarshalError
  Message: The monitoring operator goes Degraded=True when the user monitoring workflow is enabled due to DNS changes. https://access.redhat.com/solutions/6092191

  ...other conditional-and-not-allowed-for-this-cluster and conditional-but-could-not-evaluate..
```

They could update to a recommended release easily:

```console
$ oc adm upgrade --to 4.6.43
```

Or, after opting in with `--allow-not-recommended`, along a supported but not recommended path:

```console
$ oc adm upgrade --allow-not-recommended --to 4.7.4
```

#### ClusterVersion history

After updating along a supported but not recommended path, the history entry would contain an `overrides` entry:

```yaml
status:
  ...
  history:
  ...
  - startedTime: 2021-08-28T02:00:00Z
    completionTime": 2021-08-28T03:00:00Z
    state: Completed
    version: 4.7.4
    image: quay.io/openshift-release-dev/ocp-release@sha256:999a6a4bd731075e389ae601b373194c6cb2c7b4dadd1ad06ef607e86476b129
    verified: true
    overrides: |
      Updating from 4.6.23 to 4.7.4 is supported, but not recommended for this cluster.

      Reason: MultipleReasons

      Clusters on vSphere Virtual Hardware Version 14 and later may experience cross-node networking issues. https://access.redhat.com/solutions/5896081

      vSphere clusters leveraging the vSphere cloud provider may lose node names which can have serious impacts on the stability of the control plane and workloads. https://bugzilla.redhat.com/show_bug.cgi?id=1942207#c3

      On clusters with a Proxy configured, the authentication operator may keep many oauth-server connections open, resulting in high memory consumption by the authentication operator and router pods. https://bugzilla.redhat.com/show_bug.cgi?id=1941840#c33
  ...
```

### Risks and Mitigations

#### Clusters moving into the vulnerable state after updating

This enhancement proposes update-acceptance preconditions to keep vulnerable clusters from updating along an edge or to a release based on the cluster's current configuration.
For some criteria, like "is the cluster on the vSphere or `None` platform?", that configuration is static; an AWS cluster is not going to become a vSphere cluster post-update.
But some criteria, like "is an HTTP or HTTPS proxy configured?" or "are there vSphere hosts with HW 14 or unknown HW version?", are more mutable.
A cluster could have no proxy configured, update from 4.6 to 4.7.4, enable a proxy, and then have trouble with [rhbz#1941840][rhbz-1941840-impact-statement].
The current proposal has no provision for warning cluster administrators about configuration changes which might prove dangerous on their current release.

It might be possible to extend the current proposal to annotate `nodes` entries in the Cincinnati JSON response with arrays of known, vulnerable transitions.
But we'd want to distinguish between the configurations which the administrator could change (proxy configuration, vSphere HW version, etc.) and avoid warning about those which could not change (infrastructure platform).
If we could declare these vulnerabilities in `nodes`, it's possible that we would want to restrict `conditionalEdges` warnings to issues which only impacted the update itself.
In that case, the cluster-version operator would populate `conditionalUpdates[].blockedClusters` to be the union of update-time issues from Cincinnati's `conditionalEdges` and target-release issues from Cincinnati's `nodes`.

While we could extend `nodes` in future enhancements to include release vulnerabilities, leaving them off this enhancement means that we would need to continue to declare those same vulnerabilities in `conditionalEdges`, at least until we created [explicit versioning for the Cincinnati graph payloads][cincinnati-graph-api-versioning].

#### Stranding supported clusters

As described [in the documentation][support-documentation], supported updates are still supported even if incoming edges are blocked, and Red Hat will eventually provide supported update paths from any supported release to the latest supported release in its z-stream.
There is a risk, with the dynamic, per-cluster graph, that targeted edge blocking removes all outgoing update recommendations for some clusters on supported releases.
This risk can be mitigated in at least two ways:

* For the fraction of customer clusters that do not [opt-out of submitting Insights/Telemetry][uploaded-telemetry-opt-out], we can monitor [the existing `cluster_version_available_updates`][uploaded-telemetry-cluster_version_available_updates] to check for clusters running older versions which are still reporting no available, recommended updates.

* We can process the graph with tooling that removes all `conditionalEdges` and look for any supported versions without exit paths.

#### Malicious conditions

An attacker who compromises a cluster's [`upstream`][api-upstream] update service can already do some fairly disruptive things, like recommend updates from 4.1.0 straight to 4.8.0.
But at the moment, the cluster administrator (or whoever is writing to [ClusterVersion's `spec.desiredUpdate`][api-desiredUpdate]) is still in the loop deciding whether or not to accept the recommendation.

With this enhancement, the cluster-version operator will begin performing more in-cluster actions automatically, such as evaluating PromQL recommended by the upstream update service.
If the Prometheus implementation is not sufficiently hardened, malicious PromQL might expose the cluster to the attacker, with the simplest attacks being computationally intensive queries which cost CPU and memory resources that the administrator would rather be spending on more important tasks.
[Future monitoring improvements][mon-1772] might reduce the risk of expensive queries.
And it's also possible to teach the cluster-version operator to reject PromQL that does not match expected patterns.

#### Clusters without local Prometheus stacks

The Prometheus and monitoring stacks are fairly resource-intensive.
There are [open proposals][mon-1569] to reduce their resource requirements.
It is possible that some future clusters decide they need to drop the Prometheus stack entirely, which would leave the CVO unable to evaluate conditions based on PromQL.
A future mitigation would be extending to support [non-PromQL filters](#non-promql-filters).

## Design Details

### Test Plan

[The graph-data repository][graph-data] should grow a presubmit test to enforce as much of the new schema as is practical.
Validating any PromQL beyond "it's a string" is probably more trouble than its worth, but we should keep an eye on Telemetry to see if any deployed cluster-version operators are reporting trouble with condition evaluation.

Extending existing mocks and stage testing with data using the new schema should be sufficient for [update service support](#update-service-support-for-the-enhanced-schema).

Adding unit tests with data from a mock Cincinnati update service should be sufficient for [cluster-version operator support](#cluster-version-operator-support-for-the-enhanced-schema).

Ad-hoc testing when landing new features should be sufficient for `oc` and the web-console, although if they have existing frameworks for comparing output with mock cluster resources, that would be great too.

### Graduation Criteria

This will be released directly to GA.

#### Dev Preview -> Tech Preview

This will be released directly to GA.

#### Tech Preview -> GA

This will be released directly to GA.

#### Removing a deprecated feature

This enhancement does not remove or deprecate any features.

### Upgrade / Downgrade Strategy

The graph-data schema is already versioned.

We have [an open RFE][ota-123] to version the Cincinnati API, but even without that, adding new optional properties (`conditionalEdges`) for new features (edges which would have previously been completely blocked) is a backwards-compatible change.

### Version Skew Strategy

Newer update services consuming older graph-data will know that they can use their 1.1.0 parser on 1.0.0 graph-data without needing to make changes.

Older update services consuming newer graph-data will know that they are missing some features unique to 1.1.0, but that they will still get something reasonable out of the data by using their 1.0.0 parser (they'll just consider all conditional edges to be complete blockers).

Newer clients talking to older update services will not receive any `conditionalEdges`, but they will understand all the data that the update service sends to them.
Older clients talking to newer update services will not notice `conditionalEdges`, so those edges will continue to be unconditionally blocked for those clients.

Newer clients consuming older ClusterVersion will not receive any `conditionalUpdates`, but they will understand all the data included in the ClusterVersion object (e.g. `availableUpdates`).
Older clients consuming newer ClusterVersion will not notice `conditionalUpdaets`, so those edges will continue to be unconditionally blocked for those clients.

## Implementation History

Major milestones in the life cycle of a proposal should be tracked in `Implementation
History.

## Drawbacks

Dynamic edge status that is dependent on cluster state makes [the graph-data repository][graph-data] a less authoritative view of the graph served to a given client at a given time, as discussed in [the *risks and mititgations* section](#risks-and-mitigations).
This is mitigated by ClusterVersion's [`status.history[].overrides'](#enhanced-clusterversion-representation), which records any cluster-version operator objections which the cluster administrator chose to override.
It is possible that cluster administrators would chose to clear that data, but it seems unlikely that they would invest significant effort in trying to cover their tracks when [the edges are supported regardless of whether they were recommended][openshift-docs-32091].

## Alternatives

### A positive edges schema in graph-data

This enhancement [extends](#enhanced-graph-data-schema-for-blocking-edges) graph-data's [existing blocked-edges schema][blocked-edges].
Graph-data does not include a positive `edges` schema.
I tried to sell folks on making edges an explicit, first-class graph-data concept in [graph-data#1][graph-data-pull-1], but lost out to loading edges dynamically from release-image metadata.
Benefit of positive edge definitions include:

* Update services would not need to load release images from a local repository in order to figure out which update sources had been baked inside.
* Accidentally adding or forgetting to block edges becomes harder to overlook when reviewing graph-data pull requests, because more data is local vs. being stored in external release images.
* No need to shift sense when converting from graph-data to Cincinnati JSON.

Drawbacks of positive edge definitions include:

* When adding new releases to candidate channels, the ART robots or parallel tooling would need to add new edges to graph-data.

### Additional data sources

The update service could switch on data scraped from Insights tarballs or other sources instead of Prometheus.
And we could extend `clusters` in future work to allow for that.
With this initial enhancement, I focused on Prometheus because it already exposes an API and provides access to lots of in-cluster data via a single [PromQL][] query string.

#### Update-service-side filtering

Instead of filtering cluster-side in the cluster-version operator, we could filter edges on the update-service side by querying [uploaded Telemetry][uploaded-telemetry] or [client-provided query parameters][cincinnati-for-openshift-request].
However, there is more data available in-cluster beyond what is uploaded as Telemetry.
And because we are [supporting edges which we do not recommend][openshift-docs-32091], we'd need to pass the reasons for not recommending those edges out to clusters anyway.
Passing enough information to make the decision completely on the cluster side is not that much more work.

Also in this space is clusters which are on restricted networks.
Those clusters could be reconfigured to ship their Telemetry or Insights uploads to local aggregators, or could have their Telemetry and Insights sneakernetted to Red Hat's central aggregators.
But client side filtering will work in restricted-network clusters without the need for any of that, especially now that [the OpenShift Update Service][osus] is making it easier to get Cincinnati responses to clusters in restricted networks.

### Failing open

Whether a conditional edge should be recommended for a given cluster depends on intent flowin from the graph-data maintainers, through update services, to the cluster version operator, and then being evaluated in-cluster.
That flow can break down at any point; for example, the update service may only understand graph-data schema 1.0.0, and not understand 1.1.0.
Or the cluster-version operator may have trouble connecting to the in-cluster Thanos/Prometheues.
In those situations, this enhancement proposal recommends blocking the edge.

An alternative approach would have been failing open, where "failed to evaluate the graph-data maintainer intentions" would result in recommending edges.
That would reduce the risk of leaving a cluster stuck without any recommended updates.
But evalution failures should trigger alerts, so the appropriate administrators can resolve the issue, and delaying an update until we can make a clear determination is safer than updating while we are unable to make a clear determination.

As a final safety valve for situations where recovering evaluation capability would take too long, confident cluster administrators can force through the update guard.

### Query coverage

[The `promql` proposal](#enhanced-graph-data-schema-for-blocking-edges) specifies a single query that allows the update service to distinguish clusters where the edge is recommended (the query returns 0) from clusters where the edge is not recommended (the query returns 1).
This allows the cluster-version operator to distinquish between the three states of `Recommended=True` (0), `Recommended=False` (1), or `Recommended=Unknonwn` (no result, for example because the query asked for metrics which the local Prometheus was failing to scrape).

#### Metadata to include when blocking a conditional request

A URI seems like the floor for metadata.
The current proposal also includes a `reason` and `message`.
The benefit is giving users some context about what they'd see if the clicked through to the detail URI.
The downside is that we need to boil the issue down to a slug and sentence or two, and that might lead to some tension about how much detail to include.

#### Non-PromQL filters

Teaching the CVO to query the local Thanos/Prometheus shouldn't be too bad (`openshift/origin` already does this).
But we could have used `platforms` or something with less granularity to simplify the initial implementation (the CVO would pull the Infrastructure resource and compare with the configured `platforms` to decide if the edge was recommended).
For now, PromQL seems like the best balance of coverage vs. complexity, because it is an already-defined format where a single string can access a large slice of cluster state.

For example, the:

```yaml
clusters:
  promql: |
    cluster_infrastructure_provider{type=~"VSphere|None"}
    or
    0 * cluster_infrastructure_provider
```

examples from [the 4.7.4 user story](#graph-data-administrators) could be replaced by a blocker entry with:

```yaml
clusters:
  platforms:
  - VSphere
  - None
```

#### Reporting recommendation freshness

Currently [`availableUpdates`][api-availableUpdates] does not have a way to declare the freshness of its contents (e.g. "based on data retrieved from the upstream update service at `$TIMESTAMP`").
We do set the `RetrievedUpdates` condition and eventually alert if there are problems retrieving updates, and the expectation is that if we aren't complaining about being stale, we're fresh enough.
We could take the same approach with `conditionalUpdates`, but now that we also have "based on evaluations of the in-cluster state at `$TIMESTAMP`" in the mix, we may want to proactively declare the time.
On the other hand, continually bumping something that's similar to the node's `lastHeartbeatTime` is a bunch of busywork for both the cluster-version operator and the API-server.
For the moment, we have decided that the additional transparency is not with it.

### Blocking CVO gates on update acceptance

[The update-client support section](#update-client-support-for-the-enhanced-schema) suggests a client-side `--allow-not-recommended` gate on choosing a supported-but-not-recommended target.
[The cluster-version operator support section](#cluster-version-operator-support-for-the-enhanced-schema) currently calls for informative, non-blocking gates to populate [`history[].overrides`](enhanced-clusterversion-representation).
But the CVO-side gate could be blocking, and require [`force`][api-force] or similar to override those guards.
A benefit would be that the [`upstream`][api-upstream] recommendation service would be much harder to casually ignore.
A drawback would be that blocking gates would be a large departure from the current lack of any gates `upstream`-based at all.
Skipping CVO-side gates entirely would make it more difficult to reconstruct the frequency of this behavior, compared to scraping it out of ClusterVersion's `history` in Insights tarballs.
For now, non-blocking CVO-side gates feel like a happy middle ground.

### Structured override history

The [enhanced ClusterVersion representation](#enhanced-clusterversion-representation) adds an `string` `overrides` history entry.
That entry could instead be structured, with slugs for each overridden condition and messages explaining the why the CVO at the time felt the condition was unhappy.
A structured entry would allow for convenient, automated analysis of frequently-overriden conditions.
But there is a risk that we would make a poor guess at structure, and need follow-up, schema-migrating changes to iterate towards better structures.
With the single string, automated consumers are restricted to a boolean "were there any overrides?", although in exceptional cases they might want to search the message for particular substrings.
And overrides themselves should be exceptional cases, so using a single string to hold a consolidated message seems like a sufficient level of engineering for the scale of this issue.
We can revisit the structure (in an awkward, schema-migrating change) if analysis of the single strings shows that actually, overrides are not as execeptional as we'd thought, if we decide we'd need additional structure to get a handle on the now-larger issue.

[api-availableUpdates]: https://github.com/openshift/api/blob/67c28690af52a69e0b8fa565916fe1b9b7f52f10/config/v1/types_cluster_version.go#L126-L133
[api-cluster-version-status]: https://github.com/openshift/api/blob/67c28690af52a69e0b8fa565916fe1b9b7f52f10/config/v1/types_cluster_version.go#L78-L134
[api-desiredUpdate]: https://github.com/openshift/api/blob/67c28690af52a69e0b8fa565916fe1b9b7f52f10/config/v1/types_cluster_version.go#L43-L57
[api-force]: https://github.com/openshift/api/blob/67c28690af52a69e0b8fa565916fe1b9b7f52f10/config/v1/types_cluster_version.go#L248-L256
[api-history]: https://github.com/openshift/api/blob/67c28690af52a69e0b8fa565916fe1b9b7f52f10/config/v1/types_cluster_version.go#L149-L193
[api-message]: https://github.com/openshift/api/blob/67c28690af52a69e0b8fa565916fe1b9b7f52f10/config/v1/types_cluster_operator.go#L135-L139
[api-reason]: https://github.com/openshift/api/blob/67c28690af52a69e0b8fa565916fe1b9b7f52f10/config/v1/types_cluster_operator.go#L131-L133
[api-upstream]: https://github.com/openshift/api/blob/67c28690af52a69e0b8fa565916fe1b9b7f52f10/config/v1/types_cluster_version.go#L59-L63
[block-edges]: https://github.com/openshift/cincinnati-graph-data/tree/29e2d0bc2bf1dbdbe07d0d7dd91ee97e11d62f28#block-edges
[blocking-4.5.3]: https://github.com/openshift/cincinnati-graph-data/commit/8e965b65e2974d0628ea775c96694f797cd02b1e#diff-72977867226ea437c178e5a90d5d7ba8
[cincinnati]: https://github.com/openshift/cincinnati
[cincinnati-api]: https://github.com/openshift/cincinnati/blob/master/docs/design/cincinnati.md
[cincinnati-for-openshift-design]: https://github.com/openshift/cincinnati/blob/master/docs/design/openshift.md
[cincinnati-for-openshift-request]: https://github.com/openshift/cincinnati/blob/master/docs/design/openshift.md#request
[cincinnati-graph-api]: https://github.com/openshift/cincinnati/blob/master/docs/design/cincinnati.md#graph-api
[cincinnati-graph-api-versioning]: https://github.com/openshift/enhancements/pull/870
[cincinnati-spec]: https://github.com/openshift/cincinnati/blob/master/docs/design/cincinnati.md
[graph-data]: https://github.com/openshift/cincinnati-graph-data
[graph-data-pull-1]: http://github.com/openshift/cincinnati-graph-data/pull/1
[graph-data-schema-version]: https://github.com/openshift/cincinnati-graph-data/tree/29e2d0bc2bf1dbdbe07d0d7dd91ee97e11d62f28#schema-version
[json-array]: https://datatracker.ietf.org/doc/html/rfc8259#section-5
[json-object]: https://datatracker.ietf.org/doc/html/rfc8259#section-4
[json-string]: https://datatracker.ietf.org/doc/html/rfc8259#section-7
[mon-1569]: https://issues.redhat.com/browse/MON-1569
[mon-1772]: https://issues.redhat.com/browse/MON-1772
[oc]: https://github.com/openshift/oc
[openshift-docs-32091]: https://github.com/openshift/openshift-docs/pull/32091
[osus]: https://docs.openshift.com/container-platform/4.8/updating/understanding-the-update-service.html
[ota-123]: https://issues.redhat.com/browse/OTA-123
[PromQL]: https://prometheus.io/docs/prometheus/latest/querying/basics/
[PromQL-or]: https://prometheus.io/docs/prometheus/latest/querying/operators/#logical-set-binary-operators
[rhbz-1838007]: https://bugzilla.redhat.com/show_bug.cgi?id=1838007
[rhbz-1858026-impact-statement]: https://bugzilla.redhat.com/show_bug.cgi?id=1858026#c28
[rhbz-1858026-impact-statement-request]: https://bugzilla.redhat.com/show_bug.cgi?id=1858026#c26
[rhbz-1941840-impact-statement]: https://bugzilla.redhat.com/show_bug.cgi?id=1941840#c33
[rhbz-1957584-impact-statement]: https://bugzilla.redhat.com/show_bug.cgi?id=1957584#c19
[support-documentation]: https://docs.openshift.com/container-platform/4.7/updating/updating-cluster-between-minor.html#upgrade-version-paths
[uploaded-telemetry]: https://docs.openshift.com/container-platform/4.7/support/remote_health_monitoring/showing-data-collected-by-remote-health-monitoring.html#showing-data-collected-from-the-cluster_showing-data-collected-by-remote-health-monitoring
[uploaded-telemetry-cluster_version_available_updates]: https://github.com/openshift/cluster-monitoring-operator/blame/e104fcc9a5c2274646ee3ac50db2cfb7905004e4/Documentation/data-collection.md#L43-L47
[uploaded-telemetry-opt-out]: https://docs.openshift.com/container-platform/4.7/support/remote_health_monitoring/opting-out-of-remote-health-reporting.html
[web-console]: https://github.com/openshift/console
