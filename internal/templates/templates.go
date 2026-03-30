package templates

import (
	"embed"
	"html/template"
	"log/slog"
	"net/http"

	gorillacsrf "github.com/gorilla/csrf"
)

//go:embed *.html
var templateFS embed.FS

//go:embed style.css
var styleCSS []byte

type Templates struct {
	tmpl *template.Template
}

func New(adminPrefix, version string) (*Templates, error) {
	funcs := template.FuncMap{
		"prefix":    func() string { return adminPrefix },
		"version":   func() string { return version },
		"csrfToken": func() string { return "" }, // placeholder, overridden per-render
	}
	tmpl, err := template.New("").Funcs(funcs).ParseFS(templateFS, "*.html")
	if err != nil {
		return nil, err
	}
	return &Templates{tmpl: tmpl}, nil
}

func (t *Templates) ServeCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(styleCSS)
}

func (t *Templates) Render(w http.ResponseWriter, r *http.Request, name string, data any) {
	token := ""
	if r != nil {
		token = gorillacsrf.Token(r)
	}
	tmpl, err := t.tmpl.Clone()
	if err != nil {
		slog.Error("template clone failed", "error", err)
		return
	}
	tmpl.Funcs(template.FuncMap{
		"csrfToken": func() string { return token },
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		slog.Error("template render failed", "template", name, "error", err)
	}
}
