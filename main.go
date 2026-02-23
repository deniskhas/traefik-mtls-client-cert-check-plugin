package mtlscls

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type Config struct {
	SecretName      string `json:"secretName"`
	SecretNamespace string `json:"secretNamespace"`
	SecretKey       string `json:"secretKey"` // Usually "ca.crt"
}

func CreateConfig() *Config {
	return &Config{}
}

type MTLSCLSValidator struct {
	next   http.Handler
	name   string
	caPool *x509.CertPool
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {

	// Create in-cluster Kubernetes client
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create in-cluster config: %w", err)
	}
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	// Read Secret from K8s
	secret, err := kubeClient.CoreV1().Secrets(config.SecretNamespace).Get(context.Background(), config.SecretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to read secret %s/%s: %w", config.SecretNamespace, config.SecretName, err)
	}

	caData, ok := secret.Data[config.SecretKey]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s missing key %s", config.SecretNamespace, config.SecretName, config.SecretKey)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caData) {
		return nil, fmt.Errorf("failed to parse CA from secret")
	}

	return &MTLSCLSValidator{
		next:   next,
		name:   name,
		caPool: pool,
	}, nil
}

// ServeHTTP implements http.Handler
func (m *MTLSCLSValidator) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
		cert := req.TLS.PeerCertificates[0]
		opts := x509.VerifyOptions{
			Roots: m.caPool,
		}

		// Separate check for expired certificate
		if cert.NotAfter.Before(time.Now()) {
			// Certificate validation failed, certificate is expired
			http.Error(rw, "Certificate is expired", http.StatusUnauthorized)
			return
		}

		if _, err := cert.Verify(opts); err != nil {
			// Certificate validation failed, return 401 Unauthorized
			http.Error(rw, "Certificate validation failed: "+err.Error(), http.StatusUnauthorized)
			return
		}
	}
	m.next.ServeHTTP(rw, req)
}
