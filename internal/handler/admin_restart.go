package handler

import (
	"net/http"
	"time"
)

// handleRestart triggers a graceful server restart.
// POST /api/admin/restart
func (h *Handler) handleRestart(w http.ResponseWriter, r *http.Request) {
	if h.restartCh == nil {
		jsonError(w, "restart not supported in this deployment", http.StatusNotImplemented)
		return
	}

	h.audit("server_restart", "admin", getClientIP(r), nil)
	jsonResp(w, map[string]string{"status": "restarting"}, http.StatusOK)

	// Delay slightly so the response gets sent
	go func() {
		time.Sleep(200 * time.Millisecond)
		select {
		case h.restartCh <- struct{}{}:
		default:
		}
	}()
}
