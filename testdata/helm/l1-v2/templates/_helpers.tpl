{{- define "sample.name" -}}sample{{- end -}}
{{- define "sample.fullname" -}}
{{ include "sample.name" . }}-{{ .Values.image.tag }}
{{- end -}}
{{- block "sample.labels" . -}}
app: sample
{{- end -}}
{{- define "sample.name" -}}duplicate{{- end -}}
