package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/Ptt-official-app/go-pttbbs/bbs"
	"github.com/Ptt-official-app/pttbbs-backend/schema"
	"github.com/Ptt-official-app/pttbbs-backend/types"
	"github.com/sirupsen/logrus"
)

// from: https://github.com/privacy-ethereum/go-zkid-verifier/blob/main/linkverify/linkverify.go
type PublicSignals = VerifierPublicSignals

// from: https://github.com/privacy-ethereum/go-zkid-verifier/blob/main/linkverify/verifier.go
type Verifier struct {
	KeysDir       string
	SmtRoot       *SmtRootProvider
	IssuerCert    *IssuerCertProvider
	ExpectedAppID string // 31-char UTF-8 string; compared constant-time against parsed proof
	Logger        SmtRootLogger
}

// SmtRootOutcome is the outcome of the proof-vs-trusted-root comparison.
type SmtRootOutcome struct {
	Issuer      SmtRootIssuerID `json:"-"`
	IssuerName  string          `json:"issuer"`
	Match       bool            `json:"match"`
	Expected    string          `json:"expected"`
	Observed    string          `json:"observed"`
	TrustSource string          `json:"trust_source,omitempty"`
	TrustedAt   time.Time       `json:"trusted_at,omitempty"`
}

type IssuerModulusOutcome struct {
	Issuer         SmtRootIssuerID `json:"-"`
	IssuerName     string          `json:"issuer"`
	Match          bool            `json:"match"`
	ExpectedSHA256 string          `json:"expected_sha256"`
	TrustSource    string          `json:"trust_source,omitempty"`
	TrustedAt      time.Time       `json:"trusted_at,omitempty"`
}

type AppIDOutcome struct {
	Match    bool   `json:"match"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
}

// ChallengeOutcome reports whether the per-session challenge in the device-sig
// proof matches the value the verifier issued for this challenge.
type ChallengeOutcome struct {
	Match    bool   `json:"match"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
}

// from: https://github.com/privacy-ethereum/go-zkid-verifier/blob/main/verifier/verifier.go
type VerifierPublicSignals struct {
	CertChain []string `json:"cert_chain"`
	UserSig   []string `json:"user_sig"`
}

// from: https://github.com/privacy-ethereum/go-zkid-verifier/blob/main/verifier/public_inputs.go
type VerifierParsedInputs struct {
	PkCommit         string   `json:"pk_commit"`
	Nullifier        string   `json:"nullifier"`
	AppID            string   `json:"app_id"`
	AppIDPacked      string   `json:"app_id_packed"`
	Challenge        string   `json:"challenge"`
	IssuerRSAModulus []string `json:"issuer_rsa_modulus"`
	SmtRoot          string   `json:"smt_root"`
}

type VerifyResponse struct {
	Verified      bool                  `json:"verified"`
	Nullifier     string                `json:"nullifier,omitempty"`
	IDVerified    bool                  `json:"id_verified,omitempty"`
	Persisted     bool                  `json:"persisted,omitempty"`
	PublicSignals *PublicSignals        `json:"public_signals,omitempty"`
	ParsedInputs  *VerifierParsedInputs `json:"parsed_inputs,omitempty"`
	SmtRoot       *SmtRootOutcome       `json:"smt_root,omitempty"`
	IssuerModulus *IssuerModulusOutcome `json:"issuer_modulus,omitempty"`
	AppID         *AppIDOutcome         `json:"app_id,omitempty"`
	Challenge     *ChallengeOutcome     `json:"challenge,omitempty"`

	Reason string `json:"reason,omitempty"`
}

// from: https://github.com/privacy-ethereum/go-zkid-verifier/blob/main/smtroot/smtroot.go

type SmtRootIssuerID int

type SmtRootRoot [32]byte

type SmtRootProvider struct {
	primary  SmtRootSource
	fallback SmtRootSource
	refresh  time.Duration
	timeout  time.Duration
	log      SmtRootLogger

	mu              sync.RWMutex
	roots           map[SmtRootIssuerID]SmtRootRoot
	sourceUsed      string
	updatedAt       time.Time
	lastAttemptAt   time.Time
	lastError       string
	consecutiveFail int
	attempts        map[string]*SmtRootAttemptStat

	stopOnce sync.Once
	stopCh   chan struct{}
}

type SmtRootSource interface {
	FetchAll(ctx context.Context) (map[SmtRootIssuerID]SmtRootRoot, error)
	Name() string
}

type SmtRootAttemptStat struct {
	Count         int64  `json:"count"`
	LastLatencyMs int64  `json:"last_latency_ms"`
	LastErr       string `json:"last_err,omitempty"`
}

// from: https://github.com/privacy-ethereum/go-zkid-verifier/blob/main/smtroot/log.go
type SmtRootLogger interface {
	Event(level, event string, kv ...any)
}

// from: https://github.com/privacy-ethereum/go-zkid-verifier/blob/main/issuercert/issuercert.go

type IssuerCertIssuerID = SmtRootIssuerID

type IssuerCertAttemptStat = SmtRootAttemptStat

type IssuerCertCertRecord struct {
	Parsed    *x509.Certificate
	PubKey    *rsa.PublicKey
	SHA256    [32]byte
	SHA256Hex string
	Limbs     []string
	Source    string
	FetchedAt time.Time
}

type IssuerCertProvider struct {
	sources map[IssuerCertIssuerID]IssuerCertSource
	refresh time.Duration
	timeout time.Duration
	log     SmtRootLogger
	now     func() time.Time

	mu              sync.RWMutex
	certs           map[IssuerCertIssuerID]*IssuerCertCertRecord
	updatedAt       time.Time
	lastAttemptAt   time.Time
	lastError       string
	consecutiveFail int
	attempts        map[string]*IssuerCertAttemptStat

	stopOnce sync.Once
	stopCh   chan struct{}
}

// from: https://github.com/privacy-ethereum/go-zkid-verifier/blob/main/issuercert/source.go
type IssuerCertSource interface {
	Issuer() IssuerCertIssuerID
	Name() string
	Fetch(ctx context.Context) ([]byte, error)
}

func NewZKProxy() *httputil.ReverseProxy {
	theURL, _ := url.Parse(types.ZK_PREFIX)
	logrus.Infof("NewZKProxy: ZK_PREFIX: %v theURL: %v", types.ZK_PREFIX, theURL)

	proxy := httputil.NewSingleHostReverseProxy(theURL)

	proxy.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Del("Access-Control-Allow-Origin")
		resp.Header.Del("Access-Control-Allow-Methods")
		resp.Header.Del("Access-Control-Allow-Headers")
		resp.Header.Del("Access-Control-Allow-Credentials")
		return nil
	}

	return proxy
}

func NewZKLinkVerifyProxy() *httputil.ReverseProxy {
	url, _ := url.Parse(types.ZK_PREFIX)

	proxy := httputil.NewSingleHostReverseProxy(url)

	proxy.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Del("Access-Control-Allow-Origin")
		resp.Header.Del("Access-Control-Allow-Methods")
		resp.Header.Del("Access-Control-Allow-Headers")
		resp.Header.Del("Access-Control-Allow-Credentials")

		// Only log successful or specific status codes if desired
		if resp.StatusCode != http.StatusOK {
			return nil
		}

		// 1. Read the body bytes
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			logrus.Errorf("ZKLinkVerifyProxy: Failed to read ZK verifier response body: %v", err)
			return err
		}
		resp.Body.Close() // Close the original body
		defer func() {
			// 4. CRITICAL: Restore the resp.Body so Gin can send it to the client
			resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}()

		// 2. Record the result (Log it, save to DB, or pass to a channel)
		var verifyResponse *VerifyResponse
		err = json.Unmarshal(bodyBytes, &verifyResponse)
		if err != nil {
			logrus.Errorf("ZKLinkVerifyProxy: unable to unmarshal: bodyBytes: %v e: %v", bodyBytes, err)
			return err
		}
		if !verifyResponse.Verified {
			return nil
		}

		// 3. schema update UserIsGovernmentID
		userID, ok := resp.Request.Context().Value(types.ZK_USER_ID_KEY).(bbs.UUserID)
		if !ok {
			return nil
		}

		nowNS := types.NowNanoTS()
		err = schema.UpdateUserIsGovernmentID(userID, verifyResponse.Verified, nowNS)
		if err != nil {
			return err
		}

		return nil
	}
	return proxy
}
