package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"filestore/client"
	"flag"
	"fmt"
	"github.com/go-session/session"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"net/http"
)

var (
	clientSecretVar string
)

func init() {
	flag.StringVar(&clientSecretVar, "s", "", "oauth secret")
}

const (
	authServerURL = "http://localhost:9096"
)

var (
	config = oauth2.Config{
		ClientID:     "395785444978-7b9v7l0ap2h3308528vu1ddnt3rqftjc.apps.huangusercontent.com",
		ClientSecret: clientSecretVar,
		Scopes:       []string{"all"},
		RedirectURL:  "http://localhost:9094/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  authServerURL + "/oauth/authorize",
			TokenURL: authServerURL + "/oauth/token",
			// todo:check valid?
		},
	}

	//globalToken *oauth2.Token // Non-concurrent security
)

func ensureLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sStore, err := session.Start(r.Context(), w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		token, ok := sStore.Get("Token")
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		resp, err := http.Get(fmt.Sprintf("%s/test?access_token=%s", authServerURL, token.AccessToken))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	// 登录函数
	http.HandleFunc("/oauth", func(w http.ResponseWriter, r *http.Request) {
		u := config.AuthCodeURL("success",
			oauth2.SetAuthURLParam("code_challenge", genCodeChallengeS256("s256example")),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"))
		http.Redirect(w, r, u, http.StatusFound)
	})

	//回调
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		state := r.Form.Get("state")
		if state != "success" {
			http.Error(w, "State invalid", http.StatusBadRequest)
			return
		}
		code := r.Form.Get("code")
		if code == "" {
			http.Error(w, "Code not found", http.StatusBadRequest)
			return
		}
		token, err := config.Exchange(context.Background(), code, oauth2.SetAuthURLParam("code_verifier", "s256example"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sStore, err := session.Start(r.Context(), w, r)
		sStore.Set("Token", token)
		w.WriteHeader(http.StatusOK)
	})
	http.Handle("/initUser", ensureLogin(http.HandlerFunc(initUser)))
	http.Handle("/getUser", ensureLogin(http.HandlerFunc(getUser)))
	http.Handle("/createNewFile", ensureLogin(http.HandlerFunc(createNewFile)))
	http.Handle("/appendToFile", ensureLogin(http.HandlerFunc(appendToFile)))
	http.Handle("/loadFile", ensureLogin(http.HandlerFunc(loadFile)))
	http.Handle("/createInvitation", ensureLogin(http.HandlerFunc(createInvitation)))
	http.Handle("/acceptInvitation", ensureLogin(http.HandlerFunc(acceptInvitation)))
	http.Handle("/revokeAccess", ensureLogin(http.HandlerFunc(revokeAccess)))

}

func createNewFile(writer http.ResponseWriter, request *http.Request) {

}

func appendToFile(writer http.ResponseWriter, request *http.Request) {

}

func loadFile(writer http.ResponseWriter, request *http.Request) {

}

func revokeAccess(writer http.ResponseWriter, request *http.Request) {
	sStore, err := session.Start(request.Context(), writer, request)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	//var user client.User
	value, ok := sStore.Get("User")
	if !ok {
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
		return
	}
	user, ok := value.(client.User)
	if !ok {
		http.Error(writer, "InternalServerError", http.StatusInternalServerError)
		return
	}
	type submitRequest struct {
		RecipientUsername string `json:"recipientUsername"`
		Filename          string `json:"filename"`
	}
	var formdata submitRequest
	err = json.NewDecoder(request.Body).Decode(&formdata)
	if err != nil {
		http.Error(writer, "StatusBadRequest", http.StatusBadRequest)
		return
	}
	err = user.RevokeAccess(formdata.Filename, formdata.RecipientUsername)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
	}
	writer.WriteHeader(200)
}

func acceptInvitation(writer http.ResponseWriter, request *http.Request) {
	sStore, err := session.Start(request.Context(), writer, request)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	//var user client.User
	value, ok := sStore.Get("User")
	if !ok {
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
		return
	}
	user, ok := value.(client.User)
	if !ok {
		http.Error(writer, "InternalServerError", http.StatusInternalServerError)
		return
	}
	type submitRequest struct {
		SenderUsername string `json:"senderUsername"`
		InvitationPtr  string `json:"invitationPtr"`
		Filename       string `json:"filename"`
	}
	var formdata submitRequest
	err = json.NewDecoder(request.Body).Decode(&formdata)
	if err != nil {
		http.Error(writer, "StatusBadRequest", http.StatusBadRequest)
		return
	}
	invitationPtr, err := uuid.Parse(formdata.InvitationPtr)
	if err != nil {
		http.Error(writer, "StatusBadRequest", http.StatusBadRequest)
		return
	}
	err = user.AcceptInvitation(formdata.SenderUsername, invitationPtr, formdata.Filename)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	writer.WriteHeader(200)
}

func createInvitation(writer http.ResponseWriter, request *http.Request) {
	sStore, err := session.Start(request.Context(), writer, request)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	//var user client.User
	value, ok := sStore.Get("User")
	if !ok {
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
		return
	}
	user, ok := value.(client.User)
	if !ok {
		http.Error(writer, "InternalServerError", http.StatusInternalServerError)
		return
	}
	type submitRequest struct {
		RecipientUsername string `json:"recipientUsername"`
		Filename          string `json:"filename"`
	}
	var formdata submitRequest
	err = json.NewDecoder(request.Body).Decode(&formdata)
	if err != nil {
		http.Error(writer, "StatusBadRequest", http.StatusBadRequest)
		return
	}
	invitationUUID, err := user.CreateInvitation(formdata.Filename, formdata.RecipientUsername)
	if err != nil {
		http.Error(writer, "InternalServerError", http.StatusInternalServerError)
		return
	}
	data := map[string]interface{}{
		"invitationUUID": invitationUUID.String(),
	}
	e := json.NewEncoder(writer)
	e.SetIndent("", "  ")
	err = e.Encode(data)
	if err != nil {
		http.Error(writer, "InternalServerError", http.StatusInternalServerError)
		return
	}
}

func getUser(writer http.ResponseWriter, request *http.Request) {
	type submitRequest struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	var formdata submitRequest
	err := json.NewDecoder(request.Body).Decode(&formdata)
	if err != nil {
		http.Error(writer, "StatusBadRequest", http.StatusBadRequest)
		return
	}
	user, err := client.GetUser(formdata.Username, formdata.Password)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusUnauthorized)
		return
	}
	sStore, err := session.Start(request.Context(), writer, request)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	sStore.Set("User", user)
}

func initUser(writer http.ResponseWriter, request *http.Request) {
	type submitRequest struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	var formdata submitRequest
	err := json.NewDecoder(request.Body).Decode(&formdata)
	if err != nil {
		http.Error(writer, "StatusBadRequest", http.StatusBadRequest)
		return
	}
	user, err := client.InitUser(formdata.Username, formdata.Password)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	sStore, err := session.Start(request.Context(), writer, request)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	sStore.Set("User", user)
}

func genCodeChallengeS256(s string) string {
	s256 := sha256.Sum256([]byte(s))
	return base64.URLEncoding.EncodeToString(s256[:])
}
