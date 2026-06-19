package webui

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AuthConfig holds token-based authentication settings for the web UI.
type AuthConfig struct {
	Token   string
	Enabled bool
}

type session struct {
	token     string
	expiresAt time.Time
}

type sessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*session
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: make(map[string]*session)}
}

func (ss *sessionStore) create(token string) string {
	id := generateSessionID()
	ss.mu.Lock()
	ss.sessions[id] = &session{
		token:     token,
		expiresAt: time.Now().Add(24 * time.Hour),
	}
	ss.mu.Unlock()
	return id
}

func (ss *sessionStore) valid(id string) bool {
	ss.mu.RLock()
	s, ok := ss.sessions[id]
	ss.mu.RUnlock()
	if !ok {
		return false
	}
	return time.Now().Before(s.expiresAt)
}

func (ss *sessionStore) delete(id string) {
	ss.mu.Lock()
	delete(ss.sessions, id)
	ss.mu.Unlock()
}

func generateSessionID() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.auth.Enabled {
			next(w, r)
			return
		}

		if header := r.Header.Get("Authorization"); header != "" {
			if token, ok := strings.CutPrefix(header, "Bearer "); ok {
				if subtle.ConstantTimeCompare([]byte(token), []byte(s.auth.Token)) == 1 {
					next(w, r)
					return
				}
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid token"})
			return
		}

		cookie, err := r.Cookie("session")
		if err == nil && s.sessions.valid(cookie.Value) {
			next(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
	}
}

func (s *Server) dashboardAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.auth.Enabled {
			next(w, r)
			return
		}

		cookie, err := r.Cookie("session")
		if err == nil && s.sessions.valid(cookie.Value) {
			next(w, r)
			return
		}

		s.handleLogin(w, r)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, _ *http.Request) {
	tmpl, err := template.ParseFS(templateFS, "templates/login.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tmpl.Execute(w, nil)
}

func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.auth.Enabled {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	var payload struct {
		Token string `json:"token"`
	}

	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
	} else {
		payload.Token = r.FormValue("token")
	}

	if subtle.ConstantTimeCompare([]byte(payload.Token), []byte(s.auth.Token)) != 1 {
		if strings.Contains(contentType, "application/json") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid token"})
		} else {
			s.handleLogin(w, r)
		}
		return
	}

	sessionID := s.sessions.create(payload.Token)
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	})

	if strings.Contains(contentType, "application/json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "authenticated"})
	} else {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		s.sessions.delete(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	if r.Method == http.MethodDelete || strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "logged_out"})
	} else {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}
