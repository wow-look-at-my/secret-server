package templates

import (
	"embed"
	"html/template"
	"log/slog"
	"net/http"
)

//go:embed *.html
var templateFS embed.FS

type Templates struct {
	tmpl *template.Template
}

func New() (*Templates, error) {
	tmpl, err := template.ParseFS(templateFS, "*.html")
	if err != nil {
		return nil, err
	}
	return &Templates{tmpl: tmpl}, nil
}

func (t *Templates) Render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.tmpl.ExecuteTemplate(w, name, data); err != nil {
		slog.Error("template render failed", "template", name, "error", err)
	}
}
