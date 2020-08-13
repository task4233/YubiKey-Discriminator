package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"encoding/hex"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	_ "github.com/koesie10/webauthn/attestation"
	"github.com/koesie10/webauthn/webauthn"
)

var storage = &Storage{
	authenticators: make(map[string]*Authenticator),
	users:          make(map[string]*User),
	userAccounts:   []UserAccount{},
	lastKeyID:      "",
}

const managementID = "name"
const port = ":10011"

// WebAuthnCtr struct has the information for webauthn
type WebAuthnCtr struct {
	W                        *webauthn.WebAuthn
	SharedUser               *User
	RegisteredUser           *User
	RegisteredAuthenticators map[string]*Authenticator
}

// New returns Web
func New() (*WebAuthnCtr, error) {
	// Create the webauthn authenticator
	_w, err := webauthn.New(&webauthn.Config{
		RelyingPartyName:   "webauthn-demo",
		Debug:              true,
		AuthenticatorStore: storage,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to make webauthn(koesie10)")
	}
	return &WebAuthnCtr{
		W:                        _w,
		SharedUser:               nil,
		RegisteredUser:           nil,
		RegisteredAuthenticators: map[string]*Authenticator{},
	}, nil
}

// CheckStartHandler handles /check/start
func (wCtrl *WebAuthnCtr) CheckStartHandler(c echo.Context) error {
	sess := SessionFromContext(c)

	var ok bool
	wCtrl.SharedUser, ok = storage.users[managementID]

	// userが存在しなかったらすぐにNoContentを返す
	if !ok {
		return c.NoContent(http.StatusNotFound)
	}
	storage.users[managementID] = wCtrl.SharedUser
	wCtrl.W.StartLogin(c.Request(), c.Response(), wCtrl.SharedUser, webauthn.WrapMap(sess.Values))
	return nil
}

// CheckFinishHandler handles /check/finish
func (wCtrl *WebAuthnCtr) CheckFinishHandler(c echo.Context) error {
	sess := SessionFromContext(c)

	wCtrl.W.FinishLogin(c.Request(), c.Response(), wCtrl.SharedUser, webauthn.WrapMap(sess.Values))

	var resUser *User
	for idx := range storage.userAccounts {
		if storage.userAccounts[idx].Key == storage.lastKeyID {
			resUser = storage.userAccounts[idx].User
		}
	}

	if resUser == nil {
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.JSON(http.StatusOK, resUser)
}

// RegistrationStartHandler handles /registration/start/:name
func (wCtrl *WebAuthnCtr) RegistrationStartHandler(c echo.Context) error {
	name := c.Param("name")

	u, ok := storage.users[name]
	if !ok {
		// ユーザが存在しない場合
		u = &User{
			Name:           name,
			Authenticators: make(map[string]*Authenticator),
		}
		storage.users[name] = u
	}

	// user名が`managementID`の時、差分を見るためにもとのAuthenticatorを持っておく
	if name == managementID {
		wCtrl.RegisteredAuthenticators = u.Authenticators
	}

	sess := SessionFromContext(c)
	wCtrl.W.StartRegistration(c.Request(), c.Response(), u, webauthn.WrapMap(sess.Values))
	return nil
}

// RegistrationFinishHandler handles /registration/finish/:name
func (wCtrl *WebAuthnCtr) RegistrationFinishHandler(c echo.Context) error {
	name := c.Param("name")

	u, ok := storage.users[name]
	if !ok {
		return c.NoContent(http.StatusNotFound)
	}

	sess := SessionFromContext(c)

	wCtrl.W.FinishRegistration(c.Request(), c.Response(), u, webauthn.WrapMap(sess.Values))

	// KeyとUserペアの登録とキャッシュした情報の削除
	if name == managementID {
		var auth *Authenticator
		var ok bool
		for key := range u.Authenticators {
			auth, ok = wCtrl.RegisteredAuthenticators[key]
			// 新しく追加されたkeyは登録前には存在していないはず
			if !ok {
				break
			}
		}

		// 一度登録したらそれ以上編集することは無い
		// ここmapで持ったほうがいい
		// 深く考えないでコーディングしてしまった......
		userSet := UserAccount{
			Key:  hex.EncodeToString(auth.ID),
			User: wCtrl.RegisteredUser,
		}
		storage.userAccounts = append(storage.userAccounts, userSet)

		// 登録したら必ず初期化
		wCtrl.RegisteredUser = nil
		wCtrl.RegisteredAuthenticators = map[string]*Authenticator{}
		storage.lastKeyID = ""
	} else {
		// 実際の名前->`managementID`の順番に登録するので、
		// 最初に登録された情報と次に登録された情報を結びつければ良い
		wCtrl.RegisteredUser = u
	}

	return nil
}

// LoginStartHandler handles /login/start/:name
func (wCtrl *WebAuthnCtr) LoginStartHandler(c echo.Context) error {
	name := c.Param("name")
	u, ok := storage.users[name]

	sess := SessionFromContext(c)

	if ok {
		wCtrl.W.StartLogin(c.Request(), c.Response(), u, webauthn.WrapMap(sess.Values))
	} else {
		wCtrl.W.StartLogin(c.Request(), c.Response(), nil, webauthn.WrapMap(sess.Values))
	}

	return nil
}

// LoginFinishHandler handles /login/finish/:name
func (wCtrl *WebAuthnCtr) LoginFinishHandler(c echo.Context) error {
	name := c.Param("name")
	u, ok := storage.users[name]

	sess := SessionFromContext(c)

	var authenticator webauthn.Authenticator
	if ok {
		authenticator = wCtrl.W.FinishLogin(c.Request(), c.Response(), u, webauthn.WrapMap(sess.Values))
	} else {
		authenticator = wCtrl.W.FinishLogin(c.Request(), c.Response(), nil, webauthn.WrapMap(sess.Values))
	}
	if authenticator == nil {
		return nil
	}

	authr, ok := authenticator.(*Authenticator)
	if !ok {
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.JSON(http.StatusOK, authr.User)
}

func main() {
	// make instance for control
	webAuthnInstance, err := New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to make WebAuthnCtr...")
		os.Exit(1)
	}

	// Create echo and set some settings
	e := echo.New()
	e.Debug = true
	e.HideBanner = true

	// Add logger and recover middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Create the cookie store with an insecure key and use the middleware so sessions are saved
	store := sessions.NewCookieStore([]byte("thisisanunsecurecookiestorepassword"))
	e.Use(session.Middleware(store), SessionMiddleware)

	// ------------------------
	// Routes
	// ------------------------
	e.GET("/", Index)

	// Identification for Yubico owner
	e.POST("/webauthn/check/start", webAuthnInstance.CheckStartHandler)
	e.POST("/webauthn/check/finish", webAuthnInstance.CheckFinishHandler)

	// Registration
	e.POST("/webauthn/registration/start/:name", webAuthnInstance.RegistrationStartHandler)
	e.POST("/webauthn/registration/finish/:name", webAuthnInstance.RegistrationFinishHandler)

	// Login
	e.POST("/webauthn/login/start/:name", webAuthnInstance.LoginStartHandler)
	e.POST("/webauthn/login/finish/:name", webAuthnInstance.LoginFinishHandler)

	// ------------------------
	// Serve
	// ------------------------
	go func() {
		if err := e.Start(port); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "Listen: %v", err)
			os.Exit(1)
		}
	}()

	// shutdown the server with a timeout of 5 seconds
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	fmt.Fprintf(os.Stderr, "Shutdown Server ... (Wait 5 seconds!)\n")

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(5)*time.Second)
	defer cancel()
	if err := e.Shutdown(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Server Shutdown: %v", err)
		os.Exit(1)
	}

	select {
	case <-ctx.Done():
		fmt.Fprintf(os.Stderr, "timeout(waited 5 seconds)")
	default:
	}
	fmt.Println("Server exits correctly")
	os.Exit(0)
}
