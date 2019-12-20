package validating

import (
	"context"
	"fmt"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	"reflect"

	opentracing "github.com/opentracing/opentracing-go"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	"github.com/slok/kubewebhook/pkg/log"
	"github.com/slok/kubewebhook/pkg/observability/metrics"
	"github.com/slok/kubewebhook/pkg/webhook"
	"github.com/slok/kubewebhook/pkg/webhook/internal/helpers"
	"github.com/slok/kubewebhook/pkg/webhook/internal/instrumenting"
)

// WebhookConfig is the Validating webhook configuration.
type WebhookConfig struct {
	Name string
	Objs []metav1.Object
}

func (c *WebhookConfig) validate() error {
	errs := ""

	if c.Name == "" {
		errs = errs + "name can't be empty"
	}

	if len(c.Objs) == 0 {
		errs = errs + "; objs can't be empty"
	}

	if errs != "" {
		return fmt.Errorf("invalid configuration: %s", errs)
	}

	return nil
}

// NewWebhook is a validating webhook and will return a webhook ready for a type of resource
// it will validate the received resources.
func NewWebhook(cfg WebhookConfig, validator Validator, ot opentracing.Tracer, recorder metrics.Recorder, logger log.Logger) (webhook.Webhook, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	if logger == nil {
		logger = log.Dummy
	}

	if recorder == nil {
		logger.Warningf("no metrics recorder active")
		recorder = metrics.Dummy
	}

	if ot == nil {
		logger.Warningf("no tracer active")
		ot = &opentracing.NoopTracer{}
	}
	// Create a custom deserializer for the received admission review request.
	runtimeScheme := runtime.NewScheme()
	v1.AddToScheme(runtimeScheme)
	codecs := serializer.NewCodecFactory(runtimeScheme)
	typeMappings := map[string]reflect.Type{}
	for _, o := range cfg.Objs {
		r, ok := o.(runtime.Object)
		if ok {
			kinds, _, err := runtimeScheme.ObjectKinds(r)
			if err != nil {
				return nil, errors.WithMessage(err, "could not get kinds for object")
			}
			if len(kinds) != 1 {
				return nil, fmt.Errorf("got unexpected number of kinds(%d) for %s", len(kinds), o)
			}
			typeMappings[kinds[0].String()] = helpers.GetK8sObjType(o)
		} else {
			return nil, fmt.Errorf("could not get runtime.Object from %s", o)
		}
	}

	// Create our webhook and wrap for instrumentation (metrics and tracing).
	return &instrumenting.Webhook{
		Webhook: &staticWebhook{
			typeLookup:   typeMappings,
			deserializer: codecs.UniversalDeserializer(),
			validator:    validator,
			cfg:          cfg,
			logger:       logger,
		},
		ReviewKind:      metrics.ValidatingReviewKind,
		WebhookName:     cfg.Name,
		MetricsRecorder: recorder,
		Tracer:          ot,
	}, nil
}

// staticWebhook it's a validating webhook implementation for a  specific statuc object type.
type staticWebhook struct {
	typeLookup   map[string]reflect.Type
	deserializer runtime.Decoder
	validator    Validator
	cfg          WebhookConfig
	logger       log.Logger
}

func (w *staticWebhook) Review(ctx context.Context, ar *admissionv1beta1.AdmissionReview) *admissionv1beta1.AdmissionResponse {
	w.logger.Debugf("reviewing request %s, named: %s/%s", ar.Request.UID, ar.Request.Namespace, ar.Request.Name)

	targetType := w.typeLookup[ar.Request.Kind.String()]
	if targetType == nil {
		err := fmt.Errorf("cannot find admission type in registered object list: %s", ar.GroupVersionKind())
		return w.toAdmissionErrorResponse(ar, err)
	}

	obj := helpers.NewK8sObj(targetType)
	runtimeObj, ok := obj.(runtime.Object)
	if !ok {
		err := fmt.Errorf("could not type assert metav1.Object to runtime.Object")
		return w.toAdmissionErrorResponse(ar, err)
	}

	// Get the object.
	_, _, err := w.deserializer.Decode(ar.Request.Object.Raw, nil, runtimeObj)
	if err != nil {
		err = fmt.Errorf("error deseralizing request raw object: %s", err)
		return w.toAdmissionErrorResponse(ar, err)
	}

	_, res, err := w.validator.Validate(ctx, obj)
	if err != nil {
		return w.toAdmissionErrorResponse(ar, err)
	}

	var status string
	if res.Valid {
		status = metav1.StatusSuccess
	}

	// Forge response.
	return &admissionv1beta1.AdmissionResponse{
		UID:     ar.Request.UID,
		Allowed: res.Valid,
		Result: &metav1.Status{
			Status:  status,
			Message: res.Message,
		},
	}
}

func (w *staticWebhook) toAdmissionErrorResponse(ar *admissionv1beta1.AdmissionReview, err error) *admissionv1beta1.AdmissionResponse {
	return helpers.ToAdmissionErrorResponse(ar.Request.UID, err, w.logger)
}
