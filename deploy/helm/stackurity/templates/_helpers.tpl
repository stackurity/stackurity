{{- define "stackurity.name" -}}{{ .Chart.Name }}{{- end -}}
{{- define "stackurity.fullname" -}}{{ printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "stackurity.labels" -}}
app.kubernetes.io/name: {{ include "stackurity.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "stackurity.selector" -}}
app.kubernetes.io/name: {{ include "stackurity.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
