module github.com/pulumi/pulumi-oci/provider

go 1.16

replace github.com/hashicorp/go-getter v1.5.0 => github.com/hashicorp/go-getter v1.4.0

require (
	github.com/hashicorp/terraform-plugin-sdk v1.17.2
	github.com/pulumi/pulumi-terraform-bridge/v3 v3.5.0
	github.com/pulumi/pulumi/sdk/v3 v3.9.1
	github.com/terraform-providers/terraform-provider-oci v1.0.19-0.20210811184455-b51ee3e6fa80
)

replace (
	github.com/pulumi/pulumi-terraform-bridge/v3 v3.5.0 => /Users/dirien/Tools/repos/pulumi-terraform-bridge
)
