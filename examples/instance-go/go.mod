module github.com/pulumi/pulumi-oci/examples/instance-go

go 1.16

replace github.com/pulumi/pulumi-oci/sdk/v4 v4.0.0 => ../../sdk/

require (
	github.com/pulumi/pulumi-oci/sdk/v4 v4.0.0
	github.com/pulumi/pulumi/sdk/v3 v3.10.2
)
