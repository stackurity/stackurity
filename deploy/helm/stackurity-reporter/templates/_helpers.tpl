{{- define "reporter.fullname" -}}
{{- if contains "stackurity-reporter" .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-stackurity-reporter" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- define "reporter.secretName" -}}{{ .Values.secret.name | default (include "reporter.fullname" .) }}{{- end -}}
{{- define "reporter.labels" -}}
app.kubernetes.io/name: stackurity-reporter
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "reporter.selector" -}}
app.kubernetes.io/name: stackurity-reporter
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
