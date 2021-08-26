// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package loadbalancer

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Backend Set resource in Oracle Cloud Infrastructure Load Balancer service.
//
// Adds a backend set to a load balancer.
//
// ## Supported Aliases
//
// * `ociLoadBalancerBackendset`
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/loadbalancer"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := loadbalancer.NewBackendSet(ctx, "testBackendSet", &loadbalancer.BackendSetArgs{
// 			HealthChecker: &loadbalancer.BackendSetHealthCheckerArgs{
// 				Protocol:          pulumi.Any(_var.Backend_set_health_checker_protocol),
// 				IntervalMs:        pulumi.Any(_var.Backend_set_health_checker_interval_ms),
// 				Port:              pulumi.Any(_var.Backend_set_health_checker_port),
// 				ResponseBodyRegex: pulumi.Any(_var.Backend_set_health_checker_response_body_regex),
// 				Retries:           pulumi.Any(_var.Backend_set_health_checker_retries),
// 				ReturnCode:        pulumi.Any(_var.Backend_set_health_checker_return_code),
// 				TimeoutInMillis:   pulumi.Any(_var.Backend_set_health_checker_timeout_in_millis),
// 				UrlPath:           pulumi.Any(_var.Backend_set_health_checker_url_path),
// 			},
// 			LoadBalancerId: pulumi.Any(oci_load_balancer_load_balancer.Test_load_balancer.Id),
// 			Policy:         pulumi.Any(_var.Backend_set_policy),
// 			LbCookieSessionPersistenceConfiguration: &loadbalancer.BackendSetLbCookieSessionPersistenceConfigurationArgs{
// 				CookieName:      pulumi.Any(_var.Backend_set_lb_cookie_session_persistence_configuration_cookie_name),
// 				DisableFallback: pulumi.Any(_var.Backend_set_lb_cookie_session_persistence_configuration_disable_fallback),
// 				Domain:          pulumi.Any(_var.Backend_set_lb_cookie_session_persistence_configuration_domain),
// 				IsHttpOnly:      pulumi.Any(_var.Backend_set_lb_cookie_session_persistence_configuration_is_http_only),
// 				IsSecure:        pulumi.Any(_var.Backend_set_lb_cookie_session_persistence_configuration_is_secure),
// 				MaxAgeInSeconds: pulumi.Any(_var.Backend_set_lb_cookie_session_persistence_configuration_max_age_in_seconds),
// 				Path:            pulumi.Any(_var.Backend_set_lb_cookie_session_persistence_configuration_path),
// 			},
// 			SessionPersistenceConfiguration: &loadbalancer.BackendSetSessionPersistenceConfigurationArgs{
// 				CookieName:      pulumi.Any(_var.Backend_set_session_persistence_configuration_cookie_name),
// 				DisableFallback: pulumi.Any(_var.Backend_set_session_persistence_configuration_disable_fallback),
// 			},
// 			SslConfiguration: &loadbalancer.BackendSetSslConfigurationArgs{
// 				CertificateName:       pulumi.Any(oci_load_balancer_certificate.Test_certificate.Name),
// 				CipherSuiteName:       pulumi.Any(_var.Backend_set_ssl_configuration_cipher_suite_name),
// 				Protocols:             pulumi.Any(_var.Backend_set_ssl_configuration_protocols),
// 				ServerOrderPreference: pulumi.Any(_var.Backend_set_ssl_configuration_server_order_preference),
// 				VerifyDepth:           pulumi.Any(_var.Backend_set_ssl_configuration_verify_depth),
// 				VerifyPeerCertificate: pulumi.Any(_var.Backend_set_ssl_configuration_verify_peer_certificate),
// 			},
// 		})
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
// **Note:** The `sessionPersistenceConfiguration` (application cookie stickiness) and `lbCookieSessionPersistenceConfiguration`
//       (LB cookie stickiness) attributes are mutually exclusive. To avoid returning an error, configure only one of these two
//       attributes per backend set.
// {{% /example %}}
//
// ## Import
//
// BackendSets can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:loadbalancer/backendSet:BackendSet test_backend_set "loadBalancers/{loadBalancerId}/backendSets/{backendSetName}"
// ```
type BackendSet struct {
	pulumi.CustomResourceState

	Backends BackendSetBackendArrayOutput `pulumi:"backends"`
	// (Updatable) The health check policy's configuration details.
	HealthChecker BackendSetHealthCheckerOutput `pulumi:"healthChecker"`
	// (Updatable) The configuration details for implementing load balancer cookie session persistence (LB cookie stickiness).
	LbCookieSessionPersistenceConfiguration BackendSetLbCookieSessionPersistenceConfigurationOutput `pulumi:"lbCookieSessionPersistenceConfiguration"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add a backend set.
	LoadBalancerId pulumi.StringOutput `pulumi:"loadBalancerId"`
	// A friendly name for the backend set. It must be unique and it cannot be changed.
	Name pulumi.StringOutput `pulumi:"name"`
	// (Updatable) The load balancer policy for the backend set. To get a list of available policies, use the [ListPolicies](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/LoadBalancerPolicy/ListPolicies) operation.  Example: `LEAST_CONNECTIONS`
	Policy pulumi.StringOutput `pulumi:"policy"`
	// (Updatable) The configuration details for implementing session persistence based on a user-specified cookie name (application cookie stickiness).
	SessionPersistenceConfiguration BackendSetSessionPersistenceConfigurationOutput `pulumi:"sessionPersistenceConfiguration"`
	// (Updatable) The load balancer's SSL handling configuration details.
	SslConfiguration BackendSetSslConfigurationPtrOutput `pulumi:"sslConfiguration"`
	State            pulumi.StringOutput                 `pulumi:"state"`
}

// NewBackendSet registers a new resource with the given unique name, arguments, and options.
func NewBackendSet(ctx *pulumi.Context,
	name string, args *BackendSetArgs, opts ...pulumi.ResourceOption) (*BackendSet, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.HealthChecker == nil {
		return nil, errors.New("invalid value for required argument 'HealthChecker'")
	}
	if args.LoadBalancerId == nil {
		return nil, errors.New("invalid value for required argument 'LoadBalancerId'")
	}
	if args.Policy == nil {
		return nil, errors.New("invalid value for required argument 'Policy'")
	}
	var resource BackendSet
	err := ctx.RegisterResource("oci:loadbalancer/backendSet:BackendSet", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetBackendSet gets an existing BackendSet resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetBackendSet(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *BackendSetState, opts ...pulumi.ResourceOption) (*BackendSet, error) {
	var resource BackendSet
	err := ctx.ReadResource("oci:loadbalancer/backendSet:BackendSet", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering BackendSet resources.
type backendSetState struct {
	Backends []BackendSetBackend `pulumi:"backends"`
	// (Updatable) The health check policy's configuration details.
	HealthChecker *BackendSetHealthChecker `pulumi:"healthChecker"`
	// (Updatable) The configuration details for implementing load balancer cookie session persistence (LB cookie stickiness).
	LbCookieSessionPersistenceConfiguration *BackendSetLbCookieSessionPersistenceConfiguration `pulumi:"lbCookieSessionPersistenceConfiguration"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add a backend set.
	LoadBalancerId *string `pulumi:"loadBalancerId"`
	// A friendly name for the backend set. It must be unique and it cannot be changed.
	Name *string `pulumi:"name"`
	// (Updatable) The load balancer policy for the backend set. To get a list of available policies, use the [ListPolicies](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/LoadBalancerPolicy/ListPolicies) operation.  Example: `LEAST_CONNECTIONS`
	Policy *string `pulumi:"policy"`
	// (Updatable) The configuration details for implementing session persistence based on a user-specified cookie name (application cookie stickiness).
	SessionPersistenceConfiguration *BackendSetSessionPersistenceConfiguration `pulumi:"sessionPersistenceConfiguration"`
	// (Updatable) The load balancer's SSL handling configuration details.
	SslConfiguration *BackendSetSslConfiguration `pulumi:"sslConfiguration"`
	State            *string                     `pulumi:"state"`
}

type BackendSetState struct {
	Backends BackendSetBackendArrayInput
	// (Updatable) The health check policy's configuration details.
	HealthChecker BackendSetHealthCheckerPtrInput
	// (Updatable) The configuration details for implementing load balancer cookie session persistence (LB cookie stickiness).
	LbCookieSessionPersistenceConfiguration BackendSetLbCookieSessionPersistenceConfigurationPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add a backend set.
	LoadBalancerId pulumi.StringPtrInput
	// A friendly name for the backend set. It must be unique and it cannot be changed.
	Name pulumi.StringPtrInput
	// (Updatable) The load balancer policy for the backend set. To get a list of available policies, use the [ListPolicies](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/LoadBalancerPolicy/ListPolicies) operation.  Example: `LEAST_CONNECTIONS`
	Policy pulumi.StringPtrInput
	// (Updatable) The configuration details for implementing session persistence based on a user-specified cookie name (application cookie stickiness).
	SessionPersistenceConfiguration BackendSetSessionPersistenceConfigurationPtrInput
	// (Updatable) The load balancer's SSL handling configuration details.
	SslConfiguration BackendSetSslConfigurationPtrInput
	State            pulumi.StringPtrInput
}

func (BackendSetState) ElementType() reflect.Type {
	return reflect.TypeOf((*backendSetState)(nil)).Elem()
}

type backendSetArgs struct {
	// (Updatable) The health check policy's configuration details.
	HealthChecker BackendSetHealthChecker `pulumi:"healthChecker"`
	// (Updatable) The configuration details for implementing load balancer cookie session persistence (LB cookie stickiness).
	LbCookieSessionPersistenceConfiguration *BackendSetLbCookieSessionPersistenceConfiguration `pulumi:"lbCookieSessionPersistenceConfiguration"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add a backend set.
	LoadBalancerId string `pulumi:"loadBalancerId"`
	// A friendly name for the backend set. It must be unique and it cannot be changed.
	Name *string `pulumi:"name"`
	// (Updatable) The load balancer policy for the backend set. To get a list of available policies, use the [ListPolicies](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/LoadBalancerPolicy/ListPolicies) operation.  Example: `LEAST_CONNECTIONS`
	Policy string `pulumi:"policy"`
	// (Updatable) The configuration details for implementing session persistence based on a user-specified cookie name (application cookie stickiness).
	SessionPersistenceConfiguration *BackendSetSessionPersistenceConfiguration `pulumi:"sessionPersistenceConfiguration"`
	// (Updatable) The load balancer's SSL handling configuration details.
	SslConfiguration *BackendSetSslConfiguration `pulumi:"sslConfiguration"`
}

// The set of arguments for constructing a BackendSet resource.
type BackendSetArgs struct {
	// (Updatable) The health check policy's configuration details.
	HealthChecker BackendSetHealthCheckerInput
	// (Updatable) The configuration details for implementing load balancer cookie session persistence (LB cookie stickiness).
	LbCookieSessionPersistenceConfiguration BackendSetLbCookieSessionPersistenceConfigurationPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add a backend set.
	LoadBalancerId pulumi.StringInput
	// A friendly name for the backend set. It must be unique and it cannot be changed.
	Name pulumi.StringPtrInput
	// (Updatable) The load balancer policy for the backend set. To get a list of available policies, use the [ListPolicies](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/LoadBalancerPolicy/ListPolicies) operation.  Example: `LEAST_CONNECTIONS`
	Policy pulumi.StringInput
	// (Updatable) The configuration details for implementing session persistence based on a user-specified cookie name (application cookie stickiness).
	SessionPersistenceConfiguration BackendSetSessionPersistenceConfigurationPtrInput
	// (Updatable) The load balancer's SSL handling configuration details.
	SslConfiguration BackendSetSslConfigurationPtrInput
}

func (BackendSetArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*backendSetArgs)(nil)).Elem()
}

type BackendSetInput interface {
	pulumi.Input

	ToBackendSetOutput() BackendSetOutput
	ToBackendSetOutputWithContext(ctx context.Context) BackendSetOutput
}

func (*BackendSet) ElementType() reflect.Type {
	return reflect.TypeOf((*BackendSet)(nil))
}

func (i *BackendSet) ToBackendSetOutput() BackendSetOutput {
	return i.ToBackendSetOutputWithContext(context.Background())
}

func (i *BackendSet) ToBackendSetOutputWithContext(ctx context.Context) BackendSetOutput {
	return pulumi.ToOutputWithContext(ctx, i).(BackendSetOutput)
}

func (i *BackendSet) ToBackendSetPtrOutput() BackendSetPtrOutput {
	return i.ToBackendSetPtrOutputWithContext(context.Background())
}

func (i *BackendSet) ToBackendSetPtrOutputWithContext(ctx context.Context) BackendSetPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(BackendSetPtrOutput)
}

type BackendSetPtrInput interface {
	pulumi.Input

	ToBackendSetPtrOutput() BackendSetPtrOutput
	ToBackendSetPtrOutputWithContext(ctx context.Context) BackendSetPtrOutput
}

type backendSetPtrType BackendSetArgs

func (*backendSetPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**BackendSet)(nil))
}

func (i *backendSetPtrType) ToBackendSetPtrOutput() BackendSetPtrOutput {
	return i.ToBackendSetPtrOutputWithContext(context.Background())
}

func (i *backendSetPtrType) ToBackendSetPtrOutputWithContext(ctx context.Context) BackendSetPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(BackendSetPtrOutput)
}

// BackendSetArrayInput is an input type that accepts BackendSetArray and BackendSetArrayOutput values.
// You can construct a concrete instance of `BackendSetArrayInput` via:
//
//          BackendSetArray{ BackendSetArgs{...} }
type BackendSetArrayInput interface {
	pulumi.Input

	ToBackendSetArrayOutput() BackendSetArrayOutput
	ToBackendSetArrayOutputWithContext(context.Context) BackendSetArrayOutput
}

type BackendSetArray []BackendSetInput

func (BackendSetArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*BackendSet)(nil)).Elem()
}

func (i BackendSetArray) ToBackendSetArrayOutput() BackendSetArrayOutput {
	return i.ToBackendSetArrayOutputWithContext(context.Background())
}

func (i BackendSetArray) ToBackendSetArrayOutputWithContext(ctx context.Context) BackendSetArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(BackendSetArrayOutput)
}

// BackendSetMapInput is an input type that accepts BackendSetMap and BackendSetMapOutput values.
// You can construct a concrete instance of `BackendSetMapInput` via:
//
//          BackendSetMap{ "key": BackendSetArgs{...} }
type BackendSetMapInput interface {
	pulumi.Input

	ToBackendSetMapOutput() BackendSetMapOutput
	ToBackendSetMapOutputWithContext(context.Context) BackendSetMapOutput
}

type BackendSetMap map[string]BackendSetInput

func (BackendSetMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*BackendSet)(nil)).Elem()
}

func (i BackendSetMap) ToBackendSetMapOutput() BackendSetMapOutput {
	return i.ToBackendSetMapOutputWithContext(context.Background())
}

func (i BackendSetMap) ToBackendSetMapOutputWithContext(ctx context.Context) BackendSetMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(BackendSetMapOutput)
}

type BackendSetOutput struct {
	*pulumi.OutputState
}

func (BackendSetOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*BackendSet)(nil))
}

func (o BackendSetOutput) ToBackendSetOutput() BackendSetOutput {
	return o
}

func (o BackendSetOutput) ToBackendSetOutputWithContext(ctx context.Context) BackendSetOutput {
	return o
}

func (o BackendSetOutput) ToBackendSetPtrOutput() BackendSetPtrOutput {
	return o.ToBackendSetPtrOutputWithContext(context.Background())
}

func (o BackendSetOutput) ToBackendSetPtrOutputWithContext(ctx context.Context) BackendSetPtrOutput {
	return o.ApplyT(func(v BackendSet) *BackendSet {
		return &v
	}).(BackendSetPtrOutput)
}

type BackendSetPtrOutput struct {
	*pulumi.OutputState
}

func (BackendSetPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**BackendSet)(nil))
}

func (o BackendSetPtrOutput) ToBackendSetPtrOutput() BackendSetPtrOutput {
	return o
}

func (o BackendSetPtrOutput) ToBackendSetPtrOutputWithContext(ctx context.Context) BackendSetPtrOutput {
	return o
}

type BackendSetArrayOutput struct{ *pulumi.OutputState }

func (BackendSetArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]BackendSet)(nil))
}

func (o BackendSetArrayOutput) ToBackendSetArrayOutput() BackendSetArrayOutput {
	return o
}

func (o BackendSetArrayOutput) ToBackendSetArrayOutputWithContext(ctx context.Context) BackendSetArrayOutput {
	return o
}

func (o BackendSetArrayOutput) Index(i pulumi.IntInput) BackendSetOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) BackendSet {
		return vs[0].([]BackendSet)[vs[1].(int)]
	}).(BackendSetOutput)
}

type BackendSetMapOutput struct{ *pulumi.OutputState }

func (BackendSetMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]BackendSet)(nil))
}

func (o BackendSetMapOutput) ToBackendSetMapOutput() BackendSetMapOutput {
	return o
}

func (o BackendSetMapOutput) ToBackendSetMapOutputWithContext(ctx context.Context) BackendSetMapOutput {
	return o
}

func (o BackendSetMapOutput) MapIndex(k pulumi.StringInput) BackendSetOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) BackendSet {
		return vs[0].(map[string]BackendSet)[vs[1].(string)]
	}).(BackendSetOutput)
}

func init() {
	pulumi.RegisterOutputType(BackendSetOutput{})
	pulumi.RegisterOutputType(BackendSetPtrOutput{})
	pulumi.RegisterOutputType(BackendSetArrayOutput{})
	pulumi.RegisterOutputType(BackendSetMapOutput{})
}
