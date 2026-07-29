package templates

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

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
		"joinLines": func(lines []string) string {
			return strings.Join(lines, "\n")
		},
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
		"timeTag": timeTag,
	}
	tmpl, err := template.New("").Funcs(funcs).ParseFS(templateFS, "*.html")
	if err != nil {
		return nil, err
	}
	return &Templates{tmpl: tmpl}, nil
}

// timeTag renders a timestamp as a <time> element carrying the RFC3339 UTC
// instant in its datetime attribute, with a plain UTC string as the no-JS
// fallback text. The inline localizer script in layout.html's "foot" block
// rewrites it into the viewer's own locale/time zone. The markup is built
// solely from time.Format output, which contains no HTML metacharacters, so
// returning template.HTML is safe here.
func timeTag(v any) template.HTML {
	var t time.Time
	switch val := v.(type) {
	case time.Time:
		t = val
	case *time.Time:
		if val == nil {
			return template.HTML("")
		}
		t = *val
	default:
		return template.HTML("")
	}
	u := t.UTC()
	return template.HTML(fmt.Sprintf(`<time datetime="%s">%s UTC</time>`,
		u.Format(time.RFC3339), u.Format("2006-01-02 15:04:05")))
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
