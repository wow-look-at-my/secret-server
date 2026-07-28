package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/wow-look-at-my/secret-server/internal/database"
)

const maxPushAttestations = 32

var (
	githubRepositoryRE = regexp.MustCompile(
		`^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/[A-Za-z0-9_.-]{1,100}$`,
	)
	githubSHA     = regexp.MustCompile(`^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$`)
	githubLoginRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)
)

type githubPushAttestation struct {
	Repository   string `json:"repository"`
	Ref          string `json:"ref"`
	SHA          string `json:"sha"`
	GitHubUserID int64  `json:"github_user_id"`
	GitHubLogin  string `json:"github_login"`
	SessionID    string `json:"session_id,omitempty"`
}

type githubPushAttestationRequest struct {
	Pushes []githubPushAttestation `json:"pushes"`
}

// authorizeGitHubPushAttester authenticates a machine credential and checks a
// permission separate from secret access. This prevents an arbitrary webhook
// token from turning itself into a trusted human-identity oracle.
func (h *PublicHandler) authorizeGitHubPushAttester(
	r *http.Request,
) (*database.MachineToken, int, error) {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return nil, http.StatusUnauthorized, errors.New("missing bearer token")
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	rec, err := h.db.LookupMachineToken(token)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if rec == nil {
		return nil, http.StatusUnauthorized, errors.New("invalid machine token")
	}
	if !rec.CanAttestGitHubPushes {
		return nil, http.StatusForbidden, errors.New(
			"machine token is not allowed to attest GitHub pushes",
		)
	}
	return rec, 0, nil
}

func (h *PublicHandler) preflightGitHubPushAttestation(
	w http.ResponseWriter,
	r *http.Request,
) {
	if _, status, err := h.authorizeGitHubPushAttester(r); err != nil {
		http.Error(w, `{"error":`+strconv.Quote(err.Error())+`}`, status)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *PublicHandler) attestGitHubPushes(w http.ResponseWriter, r *http.Request) {
	rec, status, err := h.authorizeGitHubPushAttester(r)
	if err != nil {
		http.Error(w, `{"error":`+strconv.Quote(err.Error())+`}`, status)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var request githubPushAttestationRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if len(request.Pushes) == 0 || len(request.Pushes) > maxPushAttestations {
		http.Error(w, `{"error":"pushes must contain 1 to 32 entries"}`, http.StatusBadRequest)
		return
	}
	for i := range request.Pushes {
		if err := validateGitHubPushAttestation(request.Pushes[i]); err != nil {
			http.Error(
				w,
				`{"error":`+strconv.Quote("invalid push: "+err.Error())+`}`,
				http.StatusBadRequest,
			)
			return
		}
	}

	for _, push := range request.Pushes {
		value := database.GitHubPushProvenance{
			Repository:     push.Repository,
			Ref:            push.Ref,
			SHA:            push.SHA,
			GitHubUserID:   strconv.FormatInt(push.GitHubUserID, 10),
			GitHubLogin:    push.GitHubLogin,
			MachineTokenID: rec.ID,
		}
		if err := h.db.StoreGitHubPushProvenance(r.Context(), value); err != nil {
			slog.Error("store GitHub push provenance failed", "error", err)
			http.Error(w, `{"error":"failed to store push provenance"}`, http.StatusInternalServerError)
			return
		}
		details, _ := json.Marshal(map[string]any{
			"repository":       push.Repository,
			"ref":              push.Ref,
			"sha":              push.SHA,
			"github_login":     push.GitHubLogin,
			"github_user_id":   push.GitHubUserID,
			"session_id":       push.SessionID,
			"machine_token_id": rec.ID,
		})
		if err := h.audit.CreateEntry(
			"github.push.attested",
			"agent_host",
			strconv.FormatInt(push.GitHubUserID, 10),
			"github_push",
			push.SHA,
			string(details),
		); err != nil {
			slog.Error("audit log failed for GitHub push attestation", "error", err)
		}
	}
	if err := h.db.TouchMachineToken(rec.ID); err != nil {
		slog.Warn("failed to update push attester last-used time", "error", err)
	}
	w.WriteHeader(http.StatusCreated)
}

func validateGitHubPushAttestation(value githubPushAttestation) error {
	if !githubRepositoryRE.MatchString(value.Repository) ||
		strings.HasSuffix(strings.ToLower(value.Repository), ".git") {
		return errors.New("repository must be owner/name")
	}
	if !validGitHubRef(value.Ref) {
		return errors.New("ref must be a valid heads or tags ref")
	}
	if !githubSHA.MatchString(value.SHA) {
		return errors.New("sha must be a 40 or 64 character hexadecimal object ID")
	}
	if value.GitHubUserID <= 0 {
		return errors.New("github_user_id must be positive")
	}
	if !githubLoginRE.MatchString(value.GitHubLogin) {
		return errors.New("github_login is invalid")
	}
	if len(value.SessionID) > 128 {
		return errors.New("session_id is too long")
	}
	return nil
}

func validGitHubRef(ref string) bool {
	if !(strings.HasPrefix(ref, "refs/heads/") ||
		strings.HasPrefix(ref, "refs/tags/")) {
		return false
	}
	return len(ref) <= 512 &&
		!strings.ContainsAny(ref, " \t\r\n~^:?*[\\") &&
		!strings.Contains(ref, "..") &&
		!strings.Contains(ref, "@{") &&
		!strings.Contains(ref, "//") &&
		!strings.HasSuffix(ref, "/") &&
		!strings.HasSuffix(ref, ".") &&
		!strings.HasSuffix(ref, ".lock")
}
