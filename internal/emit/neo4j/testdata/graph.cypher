// codeanalyzer-iac graph projection

// Constraints
CREATE CONSTRAINT application_id IF NOT EXISTS FOR (n:Application) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT artifact_id IF NOT EXISTS FOR (n:Artifact) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT config_key_id IF NOT EXISTS FOR (n:ConfigKey) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT helm_dependency_id IF NOT EXISTS FOR (n:HelmDependency) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT helm_chart_reference_id IF NOT EXISTS FOR (n:HelmChartReference) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT helm_named_template_id IF NOT EXISTS FOR (n:HelmNamedTemplate) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT helm_template_call_id IF NOT EXISTS FOR (n:HelmTemplateCall) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT helm_value_reference_id IF NOT EXISTS FOR (n:HelmValueReference) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT helm_resource_template_id IF NOT EXISTS FOR (n:HelmResourceTemplate) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT helm_lookup_reference_id IF NOT EXISTS FOR (n:HelmLookupReference) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT helm_render_profile_id IF NOT EXISTS FOR (n:HelmRenderProfile) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT helm_value_layer_id IF NOT EXISTS FOR (n:HelmValueLayer) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT helm_render_id IF NOT EXISTS FOR (n:HelmRender) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT iac_diagnostic_id IF NOT EXISTS FOR (n:IaCDiagnostic) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT kubernetes_resource_id IF NOT EXISTS FOR (n:KubernetesResource) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT kubernetes_resource_address_id IF NOT EXISTS FOR (n:KubernetesResourceAddress) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT identity_alias_id IF NOT EXISTS FOR (n:IdentityAlias) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT package_id IF NOT EXISTS FOR (n:Package) REQUIRE n.id IS UNIQUE;

:param nodes_Application_IaCApplication => [{id: 'can://iac/payments', neutral: {id: 'can://iac/payments'}, owned: {iac_analyzer_version: 'dev', iac_app_id: 'can://iac/payments', iac_producer: 'codeanalyzer-iac'}}];
UNWIND $nodes_Application_IaCApplication AS row
MERGE (n:Application {id: row.id})
ON CREATE SET n += row.neutral
SET n:IaCApplication
SET n += row.owned
;

:param nodes_Artifact => [{id: 'can://artifact/payments/README.md', neutral: {format: 'text', id: 'can://artifact/payments/README.md', path: 'README.md', sha256: '3b96f6aaf9c2d53b2334074f171b284f240f359abb525c616766a19b7fb0bf50', size_bytes: 11, source: '# payments\n'}, owned: {}}];
UNWIND $nodes_Artifact AS row
MERGE (n:Artifact {id: row.id})
ON CREATE SET n += row.neutral
;

:param nodes_Artifact_CodeAnalyzerIaCConfig => [{id: 'can://artifact/payments/.codeanalyzer-iac.yaml', neutral: {format: 'yaml', id: 'can://artifact/payments/.codeanalyzer-iac.yaml', path: '.codeanalyzer-iac.yaml', sha256: 'bc036bc6bd6e780a7192119720cec0602476ddd822b908aab613d00a613274e6', size_bytes: 23, source: 'version: 1\nrenders: []\n'}, owned: {iac_analyzer_version: 'dev', iac_app_id: 'can://iac/payments', iac_config_version: 1, iac_producer: 'codeanalyzer-iac'}}];
UNWIND $nodes_Artifact_CodeAnalyzerIaCConfig AS row
MERGE (n:Artifact {id: row.id})
ON CREATE SET n += row.neutral
SET n:CodeAnalyzerIaCConfig
SET n += row.owned
;

:param nodes_Artifact_HelmArtifact_HelmCRD_IaCArtifact => [{id: 'can://artifact/payments/charts/api/crds/widget.yaml', neutral: {format: 'yaml', id: 'can://artifact/payments/charts/api/crds/widget.yaml', path: 'charts/api/crds/widget.yaml', sha256: '15eccff2269fd6ecb58381f0ff86eee35f28fb7b5a259a7d2fd4455966e6ef4d', size_bytes: 31, source: 'kind: CustomResourceDefinition\n'}, owned: {helm_roles: ['crd'], iac_analyzer_version: 'dev', iac_app_id: 'can://iac/payments', iac_dialect: 'helm', iac_kind: 'helm_crd', iac_producer: 'codeanalyzer-iac', iac_status: 'complete'}}];
UNWIND $nodes_Artifact_HelmArtifact_HelmCRD_IaCArtifact AS row
MERGE (n:Artifact {id: row.id})
ON CREATE SET n += row.neutral
SET n:HelmArtifact:HelmCRD:IaCArtifact
SET n += row.owned
;

:param nodes_Artifact_HelmArtifact_HelmChart_IaCArtifact => [{id: 'can://artifact/payments/charts/api/Chart.yaml', neutral: {format: 'yaml', id: 'can://artifact/payments/charts/api/Chart.yaml', path: 'charts/api/Chart.yaml', sha256: '32c873c4e3d3068113634e23ff3d3fabdd84dfe55b57c78d03f70bda1d8c0f67', size_bytes: 40, source: 'apiVersion: v2\nname: api\nversion: 1.2.3\n'}, owned: {helm_annotations_json: '{"category":"Infrastructure"}', helm_api_version: 'v2', helm_app_version: '1.2.3', helm_chart_type: 'application', helm_deprecated: true, helm_description: 'payments API chart', helm_home: 'https://example.test', helm_icon: 'https://example.test/icon.png', helm_keywords: ['api', 'payments'], helm_kube_version: '>=1.28.0', helm_maintainers_json: '[{"name":"Platform","email":"platform@example.test","url":"https://example.test/team"}]', helm_name: 'api', helm_sources: ['https://git.example.test/api'], helm_version: '1.2.3', iac_analyzer_version: 'dev', iac_app_id: 'can://iac/payments', iac_dialect: 'helm', iac_kind: 'helm_chart', iac_producer: 'codeanalyzer-iac', iac_status: 'complete'}}, {id: 'can://artifact/payments/charts/db/Chart.yaml', neutral: {format: 'yaml', id: 'can://artifact/payments/charts/db/Chart.yaml', path: 'charts/db/Chart.yaml', sha256: '29fdbdd03588cd51161c879e56092975145ab171c07939777369c30d3c4cefa1', size_bytes: 39, source: 'apiVersion: v2\nname: db\nversion: 4.5.6\n'}, owned: {helm_api_version: 'v2', helm_name: 'db', helm_version: '4.5.6', iac_analyzer_version: 'dev', iac_app_id: 'can://iac/payments', iac_dialect: 'helm', iac_kind: 'helm_chart', iac_producer: 'codeanalyzer-iac', iac_status: 'complete'}}];
UNWIND $nodes_Artifact_HelmArtifact_HelmChart_IaCArtifact AS row
MERGE (n:Artifact {id: row.id})
ON CREATE SET n += row.neutral
SET n:HelmArtifact:HelmChart:IaCArtifact
SET n += row.owned
;

:param nodes_Artifact_HelmArtifact_HelmIgnore_IaCArtifact => [{id: 'can://artifact/payments/charts/api/.helmignore', neutral: {format: 'text', id: 'can://artifact/payments/charts/api/.helmignore', path: 'charts/api/.helmignore', sha256: 'cd626bd30aa3875cc7c01d50050e4f88e84d4691457209871f27494ffd5f4ab4', size_bytes: 6, source: '*.tmp\n'}, owned: {helm_roles: ['ignore'], iac_analyzer_version: 'dev', iac_app_id: 'can://iac/payments', iac_dialect: 'helm', iac_kind: 'helm_ignore', iac_producer: 'codeanalyzer-iac', iac_status: 'complete'}}];
UNWIND $nodes_Artifact_HelmArtifact_HelmIgnore_IaCArtifact AS row
MERGE (n:Artifact {id: row.id})
ON CREATE SET n += row.neutral
SET n:HelmArtifact:HelmIgnore:IaCArtifact
SET n += row.owned
;

:param nodes_Artifact_HelmArtifact_HelmLock_IaCArtifact => [{id: 'can://artifact/payments/charts/api/Chart.lock', neutral: {format: 'text', id: 'can://artifact/payments/charts/api/Chart.lock', path: 'charts/api/Chart.lock', sha256: '568c092a1d4f28424e3df8d8aa2d2fc738e14c32d8854f970d69bb480e476afd', size_bytes: 17, source: 'dependencies: []\n'}, owned: {helm_roles: ['dependency_lock'], iac_analyzer_version: 'dev', iac_app_id: 'can://iac/payments', iac_dialect: 'helm', iac_kind: 'helm_lock', iac_producer: 'codeanalyzer-iac', iac_status: 'complete'}}];
UNWIND $nodes_Artifact_HelmArtifact_HelmLock_IaCArtifact AS row
MERGE (n:Artifact {id: row.id})
ON CREATE SET n += row.neutral
SET n:HelmArtifact:HelmLock:IaCArtifact
SET n += row.owned
;

:param nodes_Artifact_HelmArtifact_HelmRequirements_IaCArtifact => [{id: 'can://artifact/payments/charts/api/requirements.yaml', neutral: {format: 'yaml', id: 'can://artifact/payments/charts/api/requirements.yaml', path: 'charts/api/requirements.yaml', sha256: '568c092a1d4f28424e3df8d8aa2d2fc738e14c32d8854f970d69bb480e476afd', size_bytes: 17, source: 'dependencies: []\n'}, owned: {helm_roles: ['dependency_declaration'], iac_analyzer_version: 'dev', iac_app_id: 'can://iac/payments', iac_dialect: 'helm', iac_kind: 'helm_requirements', iac_producer: 'codeanalyzer-iac', iac_status: 'complete'}}];
UNWIND $nodes_Artifact_HelmArtifact_HelmRequirements_IaCArtifact AS row
MERGE (n:Artifact {id: row.id})
ON CREATE SET n += row.neutral
SET n:HelmArtifact:HelmRequirements:IaCArtifact
SET n += row.owned
;

:param nodes_Artifact_HelmArtifact_HelmTemplate_IaCArtifact => [{id: 'can://artifact/payments/charts/api/templates/deployment.yaml', neutral: {format: 'yaml', id: 'can://artifact/payments/charts/api/templates/deployment.yaml', path: 'charts/api/templates/deployment.yaml', sha256: 'ff55b6d75535a5a3babf3e7bb89fbc657e461cc4f79bf7ea91af52b62cc49e22', size_bytes: 114, source: 'kind: Deployment # it\'s "quoted" `backticked` $dollar \\ ünïcödé ☃\ndata:\n  password: s3cr3t-plaintext-canary\n'}, owned: {helm_roles: ['template'], iac_analyzer_version: 'dev', iac_app_id: 'can://iac/payments', iac_dialect: 'helm', iac_kind: 'helm_template', iac_producer: 'codeanalyzer-iac', iac_status: 'complete'}}];
UNWIND $nodes_Artifact_HelmArtifact_HelmTemplate_IaCArtifact AS row
MERGE (n:Artifact {id: row.id})
ON CREATE SET n += row.neutral
SET n:HelmArtifact:HelmTemplate:IaCArtifact
SET n += row.owned
;

:param nodes_Artifact_HelmArtifact_HelmValuesSchema_IaCArtifact => [{id: 'can://artifact/payments/charts/api/values.schema.json', neutral: {format: 'json', id: 'can://artifact/payments/charts/api/values.schema.json', path: 'charts/api/values.schema.json', sha256: '9091a8164f97eaca182b3d06d0e5a59e923c880ebc0148056c453c651f5b46cb', size_bytes: 18, source: '{"type":"object"}\n'}, owned: {helm_roles: ['values_schema'], iac_analyzer_version: 'dev', iac_app_id: 'can://iac/payments', iac_dialect: 'helm', iac_kind: 'helm_values_schema', iac_producer: 'codeanalyzer-iac', iac_status: 'complete'}}];
UNWIND $nodes_Artifact_HelmArtifact_HelmValuesSchema_IaCArtifact AS row
MERGE (n:Artifact {id: row.id})
ON CREATE SET n += row.neutral
SET n:HelmArtifact:HelmValuesSchema:IaCArtifact
SET n += row.owned
;

:param nodes_Artifact_HelmArtifact_HelmValues_IaCArtifact => [{id: 'can://artifact/payments/charts/api/values.yaml', neutral: {format: 'yaml', id: 'can://artifact/payments/charts/api/values.yaml', path: 'charts/api/values.yaml', sha256: 'be6362d21f5d9da9f042f0a5bd9b56dc095e16d476d5ce12383fc1aa4ccd812d', size_bytes: 22, source: 'image:\n  tag: "1.2.3"\n'}, owned: {helm_roles: ['default_values'], iac_analyzer_version: 'dev', iac_app_id: 'can://iac/payments', iac_dialect: 'helm', iac_kind: 'helm_values', iac_producer: 'codeanalyzer-iac', iac_status: 'complete'}}];
UNWIND $nodes_Artifact_HelmArtifact_HelmValues_IaCArtifact AS row
MERGE (n:Artifact {id: row.id})
ON CREATE SET n += row.neutral
SET n:HelmArtifact:HelmValues:IaCArtifact
SET n += row.owned
;

:param nodes_ConfigKey => [{id: 'can://artifact/payments/.codeanalyzer-iac.yaml@key/version', neutral: {id: 'can://artifact/payments/.codeanalyzer-iac.yaml@key/version', name: 'version', path: 'version', span_json: '{"start":[1,1],"end":[1,2],"bytes":[0,23]}'}, owned: {}}];
UNWIND $nodes_ConfigKey AS row
MERGE (n:ConfigKey {id: row.id})
ON CREATE SET n += row.neutral
;

:param nodes_ConfigKey_HelmValue_IaCValue => [{id: 'can://artifact/payments/charts/api/values.yaml@key/image.tag', neutral: {id: 'can://artifact/payments/charts/api/values.yaml@key/image.tag', name: 'tag', path: 'image.tag', span_json: '{"start":[1,1],"end":[1,2],"bytes":[0,22]}'}, owned: {iac_analyzer_version: 'dev', iac_app_id: 'can://iac/payments', iac_kind: 'helm_value', iac_producer: 'codeanalyzer-iac'}}];
UNWIND $nodes_ConfigKey_HelmValue_IaCValue AS row
MERGE (n:ConfigKey {id: row.id})
ON CREATE SET n += row.neutral
SET n:HelmValue:IaCValue
SET n += row.owned
;

:param nodes_HelmChartReference => [{id: 'can://iac/payments/helm/charts%2Fapi%2FChart.yaml/chart-reference/db', neutral: {}, owned: {analyzer_version: 'dev', iac_app_id: 'can://iac/payments', id: 'can://iac/payments/helm/charts%2Fapi%2FChart.yaml/chart-reference/db', name: 'db', producer: 'codeanalyzer-iac', purl: 'pkg:oci/db@4.5.6', repository: 'https://charts.example.test', resolved_chart_id: 'can://artifact/payments/charts/db/Chart.yaml', version_constraint: '~4.5.0'}}];
UNWIND $nodes_HelmChartReference AS row
MERGE (n:HelmChartReference {id: row.id})
SET n += row.owned
;

:param nodes_HelmDependency => [{id: 'can://iac/payments/helm/charts%2Fapi%2FChart.yaml/dependency/db', neutral: {}, owned: {alias: 'database', analyzer_version: 'dev', condition: 'db.enabled', iac_app_id: 'can://iac/payments', id: 'can://iac/payments/helm/charts%2Fapi%2FChart.yaml/dependency/db', import_values_json: '["defaults",{"child":"child.path","parent":"parent.path"}]', name: 'db', producer: 'codeanalyzer-iac', repository: 'https://charts.example.test', span_json: '{"start":[1,1],"end":[1,2],"bytes":[0,40]}', tags: ['data', 'db'], version_constraint: '~4.5.0'}}];
UNWIND $nodes_HelmDependency AS row
MERGE (n:HelmDependency {id: row.id})
SET n += row.owned
;

:param nodes_HelmDiagnostic_IaCDiagnostic => [{id: 'can://iac/payments/helm/chart/charts%2Fapi/render/production@f00d/diagnostic/IAC_HELM_RENDER_PARTIAL', neutral: {}, owned: {analyzer_version: 'dev', code: 'IAC_HELM_RENDER_PARTIAL', iac_app_id: 'can://iac/payments', id: 'can://iac/payments/helm/chart/charts%2Fapi/render/production@f00d/diagnostic/IAC_HELM_RENDER_PARTIAL', message: 'one document was skipped', phase: 'template', producer: 'codeanalyzer-iac', severity: 'warning'}}, {id: 'can://iac/payments/helm/diagnostic/IAC_HELM_UNRESOLVED_VALUE/image.tag', neutral: {}, owned: {analyzer_version: 'dev', artifact_id: 'can://artifact/payments/charts/api/templates/deployment.yaml', code: 'IAC_HELM_UNRESOLVED_VALUE', iac_app_id: 'can://iac/payments', id: 'can://iac/payments/helm/diagnostic/IAC_HELM_UNRESOLVED_VALUE/image.tag', message: 'value path "image.tag" is `unresolved` for $release', phase: 'values', producer: 'codeanalyzer-iac', severity: 'error', span_json: '{"start":[1,1],"end":[1,2],"bytes":[0,1]}'}}];
UNWIND $nodes_HelmDiagnostic_IaCDiagnostic AS row
MERGE (n:IaCDiagnostic {id: row.id})
SET n:HelmDiagnostic
SET n += row.owned
;

:param nodes_HelmLookupReference => [{id: 'can://iac/payments/helm/charts%2Fapi%2Ftemplates%2Fdeployment.yaml/lookup-reference@1:3', neutral: {}, owned: {analyzer_version: 'dev', group_expression: '', iac_app_id: 'can://iac/payments', id: 'can://iac/payments/helm/charts%2Fapi%2Ftemplates%2Fdeployment.yaml/lookup-reference@1:3', name_expression: 'api', namespace_expression: '.Release.Namespace', producer: 'codeanalyzer-iac', resource_kind_expression: 'Secret', span_json: '{"start":[1,1],"end":[1,2],"bytes":[0,114]}', version_expression: 'v1'}}];
UNWIND $nodes_HelmLookupReference AS row
MERGE (n:HelmLookupReference {id: row.id})
SET n += row.owned
;

:param nodes_HelmNamedTemplate => [{id: 'can://iac/payments/helm/charts%2Fapi%2Ftemplates%2Fdeployment.yaml/named-template/api.fullname', neutral: {}, owned: {analyzer_version: 'dev', iac_app_id: 'can://iac/payments', id: 'can://iac/payments/helm/charts%2Fapi%2Ftemplates%2Fdeployment.yaml/named-template/api.fullname', name: 'api.fullname', producer: 'codeanalyzer-iac', span_json: '{"start":[1,1],"end":[1,2],"bytes":[0,114]}'}}];
UNWIND $nodes_HelmNamedTemplate AS row
MERGE (n:HelmNamedTemplate {id: row.id})
SET n += row.owned
;

:param nodes_HelmRender => [{id: 'can://iac/payments/helm/chart/charts%2Fapi/render/production@f00d', neutral: {}, owned: {analyzer_version: 'dev', effective_values_sha256: '46e0876178516073c5ae0fb62d07c070fe57249cbad44068272a7ad9373143ab', iac_app_id: 'can://iac/payments', id: 'can://iac/payments/helm/chart/charts%2Fapi/render/production@f00d', phase: 'template', producer: 'codeanalyzer-iac', profile_id: 'can://iac/payments/config/profile/production', renderer_name: 'helm', renderer_version: '4.2.4', status: 'succeeded', value_layer_ids: ['can://iac/payments/config/profile/production/value-layer/0000', 'can://iac/payments/config/profile/production/value-layer/0001']}}];
UNWIND $nodes_HelmRender AS row
MERGE (n:HelmRender {id: row.id})
SET n += row.owned
;

:param nodes_HelmRenderProfile => [{id: 'can://iac/payments/config/profile/production', neutral: {}, owned: {analyzer_version: 'dev', api_versions: ['apps/v1'], chart_id: 'can://artifact/payments/charts/api/Chart.yaml', iac_app_id: 'can://iac/payments', id: 'can://iac/payments/config/profile/production', kube_version: '1.29.0', name: 'production', namespace: 'prod', origin: 'config', producer: 'codeanalyzer-iac', release_name: 'api-prod'}}, {id: 'can://iac/payments/helm/chart/charts%2Fapi/profile/default', neutral: {}, owned: {analyzer_version: 'dev', api_versions: [], chart_id: 'can://artifact/payments/charts/api/Chart.yaml', iac_app_id: 'can://iac/payments', id: 'can://iac/payments/helm/chart/charts%2Fapi/profile/default', name: 'default', namespace: 'default', origin: 'default', producer: 'codeanalyzer-iac', release_name: 'api'}}];
UNWIND $nodes_HelmRenderProfile AS row
MERGE (n:HelmRenderProfile {id: row.id})
SET n += row.owned
;

:param nodes_HelmResourceTemplate => [{id: 'can://iac/payments/helm/charts%2Fapi%2Ftemplates%2Fdeployment.yaml/resource-template@1:1', neutral: {}, owned: {analyzer_version: 'dev', document_index: 0, iac_app_id: 'can://iac/payments', id: 'can://iac/payments/helm/charts%2Fapi%2Ftemplates%2Fdeployment.yaml/resource-template@1:1', producer: 'codeanalyzer-iac', span_json: '{"start":[1,1],"end":[1,2],"bytes":[0,114]}'}}];
UNWIND $nodes_HelmResourceTemplate AS row
MERGE (n:HelmResourceTemplate {id: row.id})
SET n += row.owned
;

:param nodes_HelmTemplateCall => [{id: 'can://iac/payments/helm/charts%2Fapi%2Ftemplates%2Fdeployment.yaml/template-call@1:1', neutral: {}, owned: {analyzer_version: 'dev', call_kind: 'include', iac_app_id: 'can://iac/payments', id: 'can://iac/payments/helm/charts%2Fapi%2Ftemplates%2Fdeployment.yaml/template-call@1:1', name_expression: 'api.fullname', producer: 'codeanalyzer-iac', span_json: '{"start":[1,1],"end":[1,2],"bytes":[0,114]}', target_id: 'can://iac/payments/helm/charts%2Fapi%2Ftemplates%2Fdeployment.yaml/named-template/api.fullname'}}];
UNWIND $nodes_HelmTemplateCall AS row
MERGE (n:HelmTemplateCall {id: row.id})
SET n += row.owned
;

:param nodes_HelmValueLayer => [{id: 'can://iac/payments/config/profile/production/value-layer/0000', neutral: {}, owned: {analyzer_version: 'dev', iac_app_id: 'can://iac/payments', id: 'can://iac/payments/config/profile/production/value-layer/0000', ordinal: 0, producer: 'codeanalyzer-iac', source_id: 'can://artifact/payments/charts/api/values.yaml'}}, {id: 'can://iac/payments/config/profile/production/value-layer/0001', neutral: {}, owned: {analyzer_version: 'dev', iac_app_id: 'can://iac/payments', id: 'can://iac/payments/config/profile/production/value-layer/0001', ordinal: 1, producer: 'codeanalyzer-iac', source_id: 'can://artifact/payments/charts/api/values.yaml@key/image.tag'}}];
UNWIND $nodes_HelmValueLayer AS row
MERGE (n:HelmValueLayer {id: row.id})
SET n += row.owned
;

:param nodes_HelmValueReference => [{id: 'can://iac/payments/helm/charts%2Fapi%2Ftemplates%2Fdeployment.yaml/value-reference@1:2', neutral: {}, owned: {analyzer_version: 'dev', iac_app_id: 'can://iac/payments', id: 'can://iac/payments/helm/charts%2Fapi%2Ftemplates%2Fdeployment.yaml/value-reference@1:2', path_expression: 'image.tag', producer: 'codeanalyzer-iac', span_json: '{"start":[1,1],"end":[1,2],"bytes":[0,114]}', target_id: 'can://artifact/payments/charts/api/values.yaml@key/image.tag'}}];
UNWIND $nodes_HelmValueReference AS row
MERGE (n:HelmValueReference {id: row.id})
SET n += row.owned
;

:param nodes_IaCAlias_IdentityAlias => [{id: 'can://iac/payments/helm/address/core/Secret/prod/api', neutral: {}, owned: {analyzer_version: 'dev', iac_app_id: 'can://iac/payments', iac_kind: 'kubernetes_resource_address', id: 'can://iac/payments/helm/address/core/Secret/prod/api', producer: 'codeanalyzer-iac', target: 'can://iac/payments/kubernetes/core/Secret/prod/api'}}, {id: 'can://iac/payments/helm/chart/charts%2Fapi', neutral: {}, owned: {analyzer_version: 'dev', iac_app_id: 'can://iac/payments', iac_kind: 'helm_chart', id: 'can://iac/payments/helm/chart/charts%2Fapi', producer: 'codeanalyzer-iac', target: 'can://artifact/payments/charts/api/Chart.yaml'}}];
UNWIND $nodes_IaCAlias_IdentityAlias AS row
MERGE (n:IdentityAlias {id: row.id})
SET n:IaCAlias
SET n += row.owned
;

:param nodes_KubernetesResource => [{id: 'can://iac/payments/helm/chart/charts%2Fapi/render/production@f00d/kubernetes/core/Secret/prod/api', neutral: {}, owned: {address_id: 'can://iac/payments/kubernetes/core/Secret/prod/api', analyzer_version: 'dev', annotations_json: '{"checksum/config":"deadbeef"}', api_version: 'v1', iac_app_id: 'can://iac/payments', id: 'can://iac/payments/helm/chart/charts%2Fapi/render/production@f00d/kubernetes/core/Secret/prod/api', labels_json: '{"app":"api","tier":"backend"}', manifest_sha256: '05b3abf2579a5eb66403cd78be557fd860633a1fe2103c7642030defe32c657f', name: 'api', namespace: 'prod', origin_ids: ['can://iac/payments/helm/charts%2Fapi%2Ftemplates%2Fdeployment.yaml/resource-template@1:1'], plural: 'secrets', producer: 'codeanalyzer-iac', render_id: 'can://iac/payments/helm/chart/charts%2Fapi/render/production@f00d', resource_kind: 'Secret', secret_data_json: '{"password":{"key":"password","sha256":"7db87fcfd1e97ab8af46cc9525640e0bc70d3b6ce007c175872a6830c8bc1301"}}'}}];
UNWIND $nodes_KubernetesResource AS row
MERGE (n:KubernetesResource {id: row.id})
SET n += row.owned
;

:param nodes_KubernetesResourceAddress => [{id: 'can://iac/payments/kubernetes/core/Secret/prod/api', neutral: {}, owned: {analyzer_version: 'dev', group: '', iac_app_id: 'can://iac/payments', id: 'can://iac/payments/kubernetes/core/Secret/prod/api', name: 'api', namespace: 'prod', plural: 'secrets', producer: 'codeanalyzer-iac', resource_kind: 'Secret'}}];
UNWIND $nodes_KubernetesResourceAddress AS row
MERGE (n:KubernetesResourceAddress {id: row.id})
SET n += row.owned
;

:param nodes_Package => [{id: 'pkg:oci/db@4.5.6', neutral: {id: 'pkg:oci/db@4.5.6', purl: 'pkg:oci/db@4.5.6'}, owned: {}}];
UNWIND $nodes_Package AS row
MERGE (n:Package {id: row.id})
ON CREATE SET n += row.neutral
;

:param edges_DEFINES_CONFIG_Artifact_ConfigKey => [{dst: 'can://artifact/payments/.codeanalyzer-iac.yaml@key/version', src: 'can://artifact/payments/.codeanalyzer-iac.yaml'}, {dst: 'can://artifact/payments/charts/api/values.yaml@key/image.tag', src: 'can://artifact/payments/charts/api/values.yaml'}];
UNWIND $edges_DEFINES_CONFIG_Artifact_ConfigKey AS row
MATCH (s:Artifact {id: row.src})
MATCH (t:ConfigKey {id: row.dst})
MERGE (s)-[:DEFINES_CONFIG]->(t)
;

:param edges_HAS_ARTIFACT_Application_Artifact => [{dst: 'can://artifact/payments/.codeanalyzer-iac.yaml', src: 'can://iac/payments'}, {dst: 'can://artifact/payments/README.md', src: 'can://iac/payments'}, {dst: 'can://artifact/payments/charts/api/.helmignore', src: 'can://iac/payments'}, {dst: 'can://artifact/payments/charts/api/Chart.lock', src: 'can://iac/payments'}, {dst: 'can://artifact/payments/charts/api/Chart.yaml', src: 'can://iac/payments'}, {dst: 'can://artifact/payments/charts/api/crds/widget.yaml', src: 'can://iac/payments'}, {dst: 'can://artifact/payments/charts/api/requirements.yaml', src: 'can://iac/payments'}, {dst: 'can://artifact/payments/charts/api/templates/deployment.yaml', src: 'can://iac/payments'}, {dst: 'can://artifact/payments/charts/api/values.schema.json', src: 'can://iac/payments'}, {dst: 'can://artifact/payments/charts/api/values.yaml', src: 'can://iac/payments'}, {dst: 'can://artifact/payments/charts/db/Chart.yaml', src: 'can://iac/payments'}];
UNWIND $edges_HAS_ARTIFACT_Application_Artifact AS row
MATCH (s:Application {id: row.src})
MATCH (t:Artifact {id: row.dst})
MERGE (s)-[:HAS_ARTIFACT]->(t)
;

:param edges_IAC_ALIAS_OF_IdentityAlias_Artifact => [{dst: 'can://artifact/payments/charts/api/Chart.yaml', src: 'can://iac/payments/helm/chart/charts%2Fapi'}];
UNWIND $edges_IAC_ALIAS_OF_IdentityAlias_Artifact AS row
MATCH (s:IdentityAlias {id: row.src})
MATCH (t:Artifact {id: row.dst})
MERGE (s)-[:IAC_ALIAS_OF]->(t)
;

:param edges_IAC_ALIAS_OF_IdentityAlias_KubernetesResourceAddress => [{dst: 'can://iac/payments/kubernetes/core/Secret/prod/api', src: 'can://iac/payments/helm/address/core/Secret/prod/api'}];
UNWIND $edges_IAC_ALIAS_OF_IdentityAlias_KubernetesResourceAddress AS row
MATCH (s:IdentityAlias {id: row.src})
MATCH (t:KubernetesResourceAddress {id: row.dst})
MERGE (s)-[:IAC_ALIAS_OF]->(t)
;

:param edges_IAC_CALLS_TEMPLATE_HelmTemplateCall_HelmNamedTemplate => [{dst: 'can://iac/payments/helm/charts%2Fapi%2Ftemplates%2Fdeployment.yaml/named-template/api.fullname', src: 'can://iac/payments/helm/charts%2Fapi%2Ftemplates%2Fdeployment.yaml/template-call@1:1'}];
UNWIND $edges_IAC_CALLS_TEMPLATE_HelmTemplateCall_HelmNamedTemplate AS row
MATCH (s:HelmTemplateCall {id: row.src})
MATCH (t:HelmNamedTemplate {id: row.dst})
MERGE (s)-[:IAC_CALLS_TEMPLATE]->(t)
;

:param edges_IAC_CONFIGURED_BY_HelmRender_HelmRenderProfile => [{dst: 'can://iac/payments/config/profile/production', src: 'can://iac/payments/helm/chart/charts%2Fapi/render/production@f00d'}];
UNWIND $edges_IAC_CONFIGURED_BY_HelmRender_HelmRenderProfile AS row
MATCH (s:HelmRender {id: row.src})
MATCH (t:HelmRenderProfile {id: row.dst})
MERGE (s)-[:IAC_CONFIGURED_BY]->(t)
;

:param edges_IAC_DECLARES_DEPENDENCY_Artifact_HelmDependency => [{dst: 'can://iac/payments/helm/charts%2Fapi%2FChart.yaml/dependency/db', src: 'can://artifact/payments/charts/api/Chart.yaml'}];
UNWIND $edges_IAC_DECLARES_DEPENDENCY_Artifact_HelmDependency AS row
MATCH (s:Artifact {id: row.src})
MATCH (t:HelmDependency {id: row.dst})
MERGE (s)-[:IAC_DECLARES_DEPENDENCY]->(t)
;

:param edges_IAC_DECLARES_PROFILE_Artifact_HelmRenderProfile => [{dst: 'can://iac/payments/config/profile/production', src: 'can://artifact/payments/.codeanalyzer-iac.yaml'}, {dst: 'can://iac/payments/helm/chart/charts%2Fapi/profile/default', src: 'can://artifact/payments/charts/api/Chart.yaml'}];
UNWIND $edges_IAC_DECLARES_PROFILE_Artifact_HelmRenderProfile AS row
MATCH (s:Artifact {id: row.src})
MATCH (t:HelmRenderProfile {id: row.dst})
MERGE (s)-[:IAC_DECLARES_PROFILE]->(t)
;

:param edges_IAC_DEFINES_TEMPLATE_Artifact_HelmNamedTemplate => [{dst: 'can://iac/payments/helm/charts%2Fapi%2Ftemplates%2Fdeployment.yaml/named-template/api.fullname', src: 'can://artifact/payments/charts/api/templates/deployment.yaml'}];
UNWIND $edges_IAC_DEFINES_TEMPLATE_Artifact_HelmNamedTemplate AS row
MATCH (s:Artifact {id: row.src})
MATCH (t:HelmNamedTemplate {id: row.dst})
MERGE (s)-[:IAC_DEFINES_TEMPLATE]->(t)
;

:param edges_IAC_DERIVED_FROM_KubernetesResource_HelmResourceTemplate => [{dst: 'can://iac/payments/helm/charts%2Fapi%2Ftemplates%2Fdeployment.yaml/resource-template@1:1', src: 'can://iac/payments/helm/chart/charts%2Fapi/render/production@f00d/kubernetes/core/Secret/prod/api'}];
UNWIND $edges_IAC_DERIVED_FROM_KubernetesResource_HelmResourceTemplate AS row
MATCH (s:KubernetesResource {id: row.src})
MATCH (t:HelmResourceTemplate {id: row.dst})
MERGE (s)-[:IAC_DERIVED_FROM]->(t)
;

:param edges_IAC_HAS_ALIAS_Artifact_IdentityAlias => [{dst: 'can://iac/payments/helm/chart/charts%2Fapi', src: 'can://artifact/payments/charts/api/Chart.yaml'}, {dst: 'can://iac/payments/helm/address/core/Secret/prod/api', src: 'can://artifact/payments/charts/api/templates/deployment.yaml'}];
UNWIND $edges_IAC_HAS_ALIAS_Artifact_IdentityAlias AS row
MATCH (s:Artifact {id: row.src})
MATCH (t:IdentityAlias {id: row.dst})
MERGE (s)-[:IAC_HAS_ALIAS]->(t)
;

:param edges_IAC_HAS_DIAGNOSTIC_Artifact_IaCDiagnostic => [{dst: 'can://iac/payments/helm/diagnostic/IAC_HELM_UNRESOLVED_VALUE/image.tag', src: 'can://artifact/payments/charts/api/templates/deployment.yaml'}];
UNWIND $edges_IAC_HAS_DIAGNOSTIC_Artifact_IaCDiagnostic AS row
MATCH (s:Artifact {id: row.src})
MATCH (t:IaCDiagnostic {id: row.dst})
MERGE (s)-[:IAC_HAS_DIAGNOSTIC]->(t)
;

:param edges_IAC_HAS_DIAGNOSTIC_HelmRender_IaCDiagnostic => [{dst: 'can://iac/payments/helm/chart/charts%2Fapi/render/production@f00d/diagnostic/IAC_HELM_RENDER_PARTIAL', src: 'can://iac/payments/helm/chart/charts%2Fapi/render/production@f00d'}];
UNWIND $edges_IAC_HAS_DIAGNOSTIC_HelmRender_IaCDiagnostic AS row
MATCH (s:HelmRender {id: row.src})
MATCH (t:IaCDiagnostic {id: row.dst})
MERGE (s)-[:IAC_HAS_DIAGNOSTIC]->(t)
;

:param edges_IAC_HAS_LOOKUP_REFERENCE_Artifact_HelmLookupReference => [{dst: 'can://iac/payments/helm/charts%2Fapi%2Ftemplates%2Fdeployment.yaml/lookup-reference@1:3', src: 'can://artifact/payments/charts/api/templates/deployment.yaml'}];
UNWIND $edges_IAC_HAS_LOOKUP_REFERENCE_Artifact_HelmLookupReference AS row
MATCH (s:Artifact {id: row.src})
MATCH (t:HelmLookupReference {id: row.dst})
MERGE (s)-[:IAC_HAS_LOOKUP_REFERENCE]->(t)
;

:param edges_IAC_HAS_RENDER_Artifact_HelmRender => [{dst: 'can://iac/payments/helm/chart/charts%2Fapi/render/production@f00d', src: 'can://artifact/payments/charts/api/Chart.yaml'}];
UNWIND $edges_IAC_HAS_RENDER_Artifact_HelmRender AS row
MATCH (s:Artifact {id: row.src})
MATCH (t:HelmRender {id: row.dst})
MERGE (s)-[:IAC_HAS_RENDER]->(t)
;

:param edges_IAC_HAS_RESOURCE_TEMPLATE_Artifact_HelmResourceTemplate => [{dst: 'can://iac/payments/helm/charts%2Fapi%2Ftemplates%2Fdeployment.yaml/resource-template@1:1', src: 'can://artifact/payments/charts/api/templates/deployment.yaml'}];
UNWIND $edges_IAC_HAS_RESOURCE_TEMPLATE_Artifact_HelmResourceTemplate AS row
MATCH (s:Artifact {id: row.src})
MATCH (t:HelmResourceTemplate {id: row.dst})
MERGE (s)-[:IAC_HAS_RESOURCE_TEMPLATE]->(t)
;

:param edges_IAC_HAS_TEMPLATE_CALL_Artifact_HelmTemplateCall => [{dst: 'can://iac/payments/helm/charts%2Fapi%2Ftemplates%2Fdeployment.yaml/template-call@1:1', src: 'can://artifact/payments/charts/api/templates/deployment.yaml'}];
UNWIND $edges_IAC_HAS_TEMPLATE_CALL_Artifact_HelmTemplateCall AS row
MATCH (s:Artifact {id: row.src})
MATCH (t:HelmTemplateCall {id: row.dst})
MERGE (s)-[:IAC_HAS_TEMPLATE_CALL]->(t)
;

:param edges_IAC_HAS_VALUE_LAYER_HelmRenderProfile_HelmValueLayer => [{dst: 'can://iac/payments/config/profile/production/value-layer/0000', src: 'can://iac/payments/config/profile/production'}, {dst: 'can://iac/payments/config/profile/production/value-layer/0001', src: 'can://iac/payments/config/profile/production'}];
UNWIND $edges_IAC_HAS_VALUE_LAYER_HelmRenderProfile_HelmValueLayer AS row
MATCH (s:HelmRenderProfile {id: row.src})
MATCH (t:HelmValueLayer {id: row.dst})
MERGE (s)-[:IAC_HAS_VALUE_LAYER]->(t)
;

:param edges_IAC_HAS_VALUE_REFERENCE_Artifact_HelmValueReference => [{dst: 'can://iac/payments/helm/charts%2Fapi%2Ftemplates%2Fdeployment.yaml/value-reference@1:2', src: 'can://artifact/payments/charts/api/templates/deployment.yaml'}];
UNWIND $edges_IAC_HAS_VALUE_REFERENCE_Artifact_HelmValueReference AS row
MATCH (s:Artifact {id: row.src})
MATCH (t:HelmValueReference {id: row.dst})
MERGE (s)-[:IAC_HAS_VALUE_REFERENCE]->(t)
;

:param edges_IAC_IDENTIFIED_BY_PACKAGE_HelmChartReference_Package => [{dst: 'pkg:oci/db@4.5.6', src: 'can://iac/payments/helm/charts%2Fapi%2FChart.yaml/chart-reference/db'}];
UNWIND $edges_IAC_IDENTIFIED_BY_PACKAGE_HelmChartReference_Package AS row
MATCH (s:HelmChartReference {id: row.src})
MATCH (t:Package {id: row.dst})
MERGE (s)-[:IAC_IDENTIFIED_BY_PACKAGE]->(t)
;

:param edges_IAC_PART_OF_CHART_Artifact_Artifact => [{dst: 'can://artifact/payments/charts/api/Chart.yaml', src: 'can://artifact/payments/charts/api/.helmignore'}, {dst: 'can://artifact/payments/charts/api/Chart.yaml', src: 'can://artifact/payments/charts/api/Chart.lock'}, {dst: 'can://artifact/payments/charts/api/Chart.yaml', src: 'can://artifact/payments/charts/api/crds/widget.yaml'}, {dst: 'can://artifact/payments/charts/api/Chart.yaml', src: 'can://artifact/payments/charts/api/requirements.yaml'}, {dst: 'can://artifact/payments/charts/api/Chart.yaml', src: 'can://artifact/payments/charts/api/templates/deployment.yaml'}, {dst: 'can://artifact/payments/charts/api/Chart.yaml', src: 'can://artifact/payments/charts/api/values.schema.json'}, {dst: 'can://artifact/payments/charts/api/Chart.yaml', src: 'can://artifact/payments/charts/api/values.yaml'}];
UNWIND $edges_IAC_PART_OF_CHART_Artifact_Artifact AS row
MATCH (s:Artifact {id: row.src})
MATCH (t:Artifact {id: row.dst})
MERGE (s)-[:IAC_PART_OF_CHART]->(t)
;

:param edges_IAC_PRODUCES_HelmRender_KubernetesResource => [{dst: 'can://iac/payments/helm/chart/charts%2Fapi/render/production@f00d/kubernetes/core/Secret/prod/api', src: 'can://iac/payments/helm/chart/charts%2Fapi/render/production@f00d'}];
UNWIND $edges_IAC_PRODUCES_HelmRender_KubernetesResource AS row
MATCH (s:HelmRender {id: row.src})
MATCH (t:KubernetesResource {id: row.dst})
MERGE (s)-[:IAC_PRODUCES]->(t)
;

:param edges_IAC_READS_FROM_HelmValueLayer_Artifact => [{dst: 'can://artifact/payments/charts/api/values.yaml', src: 'can://iac/payments/config/profile/production/value-layer/0000'}];
UNWIND $edges_IAC_READS_FROM_HelmValueLayer_Artifact AS row
MATCH (s:HelmValueLayer {id: row.src})
MATCH (t:Artifact {id: row.dst})
MERGE (s)-[:IAC_READS_FROM]->(t)
;

:param edges_IAC_READS_FROM_HelmValueLayer_ConfigKey => [{dst: 'can://artifact/payments/charts/api/values.yaml@key/image.tag', src: 'can://iac/payments/config/profile/production/value-layer/0001'}];
UNWIND $edges_IAC_READS_FROM_HelmValueLayer_ConfigKey AS row
MATCH (s:HelmValueLayer {id: row.src})
MATCH (t:ConfigKey {id: row.dst})
MERGE (s)-[:IAC_READS_FROM]->(t)
;

:param edges_IAC_REFERENCES_VALUE_HelmValueReference_ConfigKey => [{dst: 'can://artifact/payments/charts/api/values.yaml@key/image.tag', src: 'can://iac/payments/helm/charts%2Fapi%2Ftemplates%2Fdeployment.yaml/value-reference@1:2'}];
UNWIND $edges_IAC_REFERENCES_VALUE_HelmValueReference_ConfigKey AS row
MATCH (s:HelmValueReference {id: row.src})
MATCH (t:ConfigKey {id: row.dst})
MERGE (s)-[:IAC_REFERENCES_VALUE]->(t)
;

:param edges_IAC_RENDERS_CHART_HelmRenderProfile_Artifact => [{dst: 'can://artifact/payments/charts/api/Chart.yaml', src: 'can://iac/payments/config/profile/production'}, {dst: 'can://artifact/payments/charts/api/Chart.yaml', src: 'can://iac/payments/helm/chart/charts%2Fapi/profile/default'}];
UNWIND $edges_IAC_RENDERS_CHART_HelmRenderProfile_Artifact AS row
MATCH (s:HelmRenderProfile {id: row.src})
MATCH (t:Artifact {id: row.dst})
MERGE (s)-[:IAC_RENDERS_CHART]->(t)
;

:param edges_IAC_RESOLVES_TO_CHART_HelmChartReference_Artifact => [{dst: 'can://artifact/payments/charts/db/Chart.yaml', src: 'can://iac/payments/helm/charts%2Fapi%2FChart.yaml/chart-reference/db'}];
UNWIND $edges_IAC_RESOLVES_TO_CHART_HelmChartReference_Artifact AS row
MATCH (s:HelmChartReference {id: row.src})
MATCH (t:Artifact {id: row.dst})
MERGE (s)-[:IAC_RESOLVES_TO_CHART]->(t)
;

:param edges_IAC_TARGETS_CHART_REFERENCE_HelmDependency_HelmChartReference => [{dst: 'can://iac/payments/helm/charts%2Fapi%2FChart.yaml/chart-reference/db', src: 'can://iac/payments/helm/charts%2Fapi%2FChart.yaml/dependency/db'}];
UNWIND $edges_IAC_TARGETS_CHART_REFERENCE_HelmDependency_HelmChartReference AS row
MATCH (s:HelmDependency {id: row.src})
MATCH (t:HelmChartReference {id: row.dst})
MERGE (s)-[:IAC_TARGETS_CHART_REFERENCE]->(t)
;

:param edges_IAC_TARGETS_RESOURCE_KubernetesResource_KubernetesResourceAddress => [{dst: 'can://iac/payments/kubernetes/core/Secret/prod/api', src: 'can://iac/payments/helm/chart/charts%2Fapi/render/production@f00d/kubernetes/core/Secret/prod/api'}];
UNWIND $edges_IAC_TARGETS_RESOURCE_KubernetesResource_KubernetesResourceAddress AS row
MATCH (s:KubernetesResource {id: row.src})
MATCH (t:KubernetesResourceAddress {id: row.dst})
MERGE (s)-[:IAC_TARGETS_RESOURCE]->(t)
;
