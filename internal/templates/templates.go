package templates

import (
	"embed"
	"encoding/json"
	"fmt"
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
		"fmtval": func(v any) string {
			switch val := v.(type) {
			case string:
				return val
			case float64:
				if val == float64(int64(val)) {
					return fmt.Sprintf("%d", int64(val))
				}
				return fmt.Sprintf("%g", val)
			case []any:
				b, _ := json.Marshal(val)
				return string(b)
			default:
				return fmt.Sprintf("%v", val)
			}
		},
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
