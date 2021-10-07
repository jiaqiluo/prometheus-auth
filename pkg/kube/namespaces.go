package kube

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/juju/errors"
	"github.com/rancher/prometheus-auth/pkg/data"
	log "github.com/sirupsen/logrus"
	authentication "k8s.io/api/authentication/v1"
	authorization "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	clientAuthentication "k8s.io/client-go/kubernetes/typed/authentication/v1"
	clientAuthorization "k8s.io/client-go/kubernetes/typed/authorization/v1"
	clientCache "k8s.io/client-go/tools/cache"
)

const (
	byTokenIndex     = "byToken"
	byProjectIDIndex = "byProjectID"
)

type Namespaces interface {
	Query(token string) data.Set
}

type namespaces struct {
	subjectAccessReviewsClient clientAuthorization.SubjectAccessReviewInterface
	tokenReviewsClient         clientAuthentication.TokenReviewInterface
	tokenTTLCache              *cache.LRUExpireCache
	reviewResultTTLCache       *cache.LRUExpireCache
	secretIndexer              clientCache.Indexer
	namespaceIndexer           clientCache.Indexer
}

func (n *namespaces) Query(token string) data.Set {
	ret, err := n.query(token)
	if err != nil {
		log.Warnln("failed to query Namespaces", errors.ErrorStack(err))
	}
	log.Infof("The query gets [%s]", ret.String())
	return ret
}

// query validates the token and returns all namespaces in the project the token belongs to
func (n *namespaces) query(token string) (data.Set, error) {
	ret := data.Set{}

	tokenNamespace, err := n.validate(token)
	if err != nil {
		return ret, err
	}
	log.Infof("tokenNamespace:[%s]", tokenNamespace)
	nsObj, exist, _ := n.namespaceIndexer.GetByKey(tokenNamespace)
	if !exist {
		return ret, errors.New("unknown namespace of token")
	}

	ns := toNamespace(nsObj)
	if ns.DeletionTimestamp != nil {
		return ret, errors.New("deleting namespace of token")
	}

	projectID, exist := getProjectID(ns)
	if !exist {
		return ret, errors.New("unknown project of token")
	}

	nsList, err := n.namespaceIndexer.ByIndex(byProjectIDIndex, projectID)
	if err != nil {
		return ret, errors.Annotatef(err, "invalid project")
	}

	for _, nsObj := range nsList {
		ns := toNamespace(nsObj)
		ret[ns.Name] = struct{}{}
	}
	return ret, nil
}

func (n *namespaces) validate(token string) (string, error) {
	username, found := n.tokenTTLCache.Get(token)
	if !found {
		// use the TokenReview API to check the token
		tr := &authentication.TokenReview{
			Spec: authentication.TokenReviewSpec{
				Token: token,
			},
		}
		tokenReviewResult, err := n.tokenReviewsClient.Create(context.TODO(), tr, meta.CreateOptions{})
		if err != nil {
			return "", errors.Annotatef(err, "failed to authenticate token")
		}
		if !tokenReviewResult.Status.Authenticated {
			return "", errors.New(fmt.Sprintf("denied token: %s", tokenReviewResult.Status.Error))
		}
		n.tokenTTLCache.Add(token, tokenReviewResult.Status.User.Username, 5*time.Minute)
		username = tokenReviewResult.Status.User.Username
	} else {
		log.Info("Found the token from the reviewResultTTLCache")
	}
	log.Infof("The username is: %s", username)
	// the Username is in the format of {kind:namespace:resource-name}
	names := strings.Split(username.(string), ":")
	serviceAccountName := names[len(names)-1]
	namespace := names[len(names)-2]
	log.Infof("serviceAccountName: %s | namespace: %s", serviceAccountName, namespace)

	_, exist := n.reviewResultTTLCache.Get(token)
	// no need to go further to check permissions if the token is from the cluster monitoring Grafana
	if exist || serviceAccountName == "cluster-monitoring" {
		return namespace, nil
	}

	// if the token is not in the cache, look it up and add to the cache if it is authorized
	projectMonitoringServiceAccountName := "project-monitoring"
	sarUser := fmt.Sprintf("system:serviceaccount:%s:%s", namespace, projectMonitoringServiceAccountName)
	log.Infof("sarUser: [%s]", sarUser)
	sar := &authorization.SubjectAccessReview{
		Spec: authorization.SubjectAccessReviewSpec{
			ResourceAttributes: &authorization.ResourceAttributes{
				Namespace: namespace,
				Verb:      "view",
				Group:     "monitoring.cattle.io",
				Resource:  "prometheus",
			},
			User: sarUser,
		},
	}
	reviewResult, err := n.subjectAccessReviewsClient.Create(context.TODO(), sar, meta.CreateOptions{})
	if err != nil {
		return "", errors.Annotatef(err, fmt.Sprintf("no permission to view prometheus in the namespace: %s", namespace))
	}

	if !reviewResult.Status.Allowed || reviewResult.Status.Denied {
		return "", errors.New(fmt.Sprintf("denied token: %s", reviewResult.Status.String()))
	}

	n.reviewResultTTLCache.Add(token, struct{}{}, 5*time.Minute)

	return namespace, nil
}

func NewNamespaces(ctx context.Context, k8sClient kubernetes.Interface) Namespaces {
	// secrets
	sec := k8sClient.CoreV1().Secrets(meta.NamespaceAll)
	secListWatch := &clientCache.ListWatch{
		ListFunc: func(options meta.ListOptions) (object runtime.Object, e error) {
			return sec.List(context.TODO(), options)
		},
		WatchFunc: func(options meta.ListOptions) (i watch.Interface, e error) {
			return sec.Watch(context.TODO(), options)
		},
	}
	secInformer := clientCache.NewSharedIndexInformer(secListWatch, &core.Secret{}, 2*time.Hour, clientCache.Indexers{byTokenIndex: secretByToken})

	// namespaces
	ns := k8sClient.CoreV1().Namespaces()
	nsListWatch := &clientCache.ListWatch{
		ListFunc: func(options meta.ListOptions) (object runtime.Object, e error) {
			return ns.List(context.TODO(), options)
		},
		WatchFunc: func(options meta.ListOptions) (i watch.Interface, e error) {
			return ns.Watch(context.TODO(), options)
		},
	}
	nsInformer := clientCache.NewSharedIndexInformer(nsListWatch, &core.Namespace{}, 10*time.Minute, clientCache.Indexers{byProjectIDIndex: namespaceByProjectID})

	// run
	go secInformer.Run(ctx.Done())
	go nsInformer.Run(ctx.Done())

	return &namespaces{
		subjectAccessReviewsClient: k8sClient.AuthorizationV1().SubjectAccessReviews(),
		tokenReviewsClient:         k8sClient.AuthenticationV1().TokenReviews(),
		tokenTTLCache:              cache.NewLRUExpireCache(1024),
		reviewResultTTLCache:       cache.NewLRUExpireCache(1024),
		secretIndexer:              secInformer.GetIndexer(),
		namespaceIndexer:           nsInformer.GetIndexer(),
	}
}

func toNamespace(obj interface{}) *core.Namespace {
	ns, ok := obj.(*core.Namespace)
	if !ok {
		return &core.Namespace{}
	}

	return ns
}

func toSecret(obj interface{}) *core.Secret {
	sec, ok := obj.(*core.Secret)
	if !ok {
		return &core.Secret{}
	}

	return sec
}

func getProjectID(ns *core.Namespace) (string, bool) {
	if ns != nil && ns.Labels != nil {
		projectID, exist := ns.Labels["field.cattle.io/projectId"]
		if exist {
			return projectID, true
		}
	}

	return "", false
}

func namespaceByProjectID(obj interface{}) ([]string, error) {
	projectID, exist := getProjectID(toNamespace(obj))
	if exist {
		return []string{projectID}, nil
	}

	return []string{}, nil
}

func secretByToken(obj interface{}) ([]string, error) {
	sec := toSecret(obj)
	if sec.Type == core.SecretTypeServiceAccountToken {
		secretToken := sec.Data[core.ServiceAccountTokenKey]
		if len(secretToken) != 0 {
			return []string{string(secretToken)}, nil
		}
	}

	return []string{}, nil
}
