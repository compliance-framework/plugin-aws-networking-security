# AWS VPC CCF Plugin

This plugin collects read-only AWS VPC networking data from EC2 and CloudWatch Logs, evaluates CCF Rego policy bundles, and emits evidence back through the CCF agent.

## Supported resource families

The collector can evaluate policies for:

- VPCs
- subnets
- security groups
- network ACLs
- route tables

## How it fits in CCF

The CCF agent starts this binary through HashiCorp `go-plugin`, passes configuration and policy paths over gRPC, and receives generated evidence through the runner callback. This repository does not call the CCF API directly.

## Default policy bundle mapping

| Repository | Behavior | Primary input |
| --- | --- | --- |
| `plugin-aws-vpc-policies` | `vpc` | `input.vpc` + `input.vpc_context` |
| `plugin-aws-vpc-subnet-policies` | `subnet` | `input.subnet` + `input.subnet_context` |
| `plugin-aws-vpc-sg-policies` | `sg` | `input.security_group` + `input.sg_context` |
| `plugin-aws-vpc-nacl-policies` | `acl` | `input.network_acl` + `input.nacl_context` |
| `plugin-aws-vpc-rt-policies` | `rt` | `input.route_table` + `input.route_table_context` |

## Configuration

The plugin expects:

- AWS credentials through the default AWS SDK credential chain
- target regions from `config.regions` or `config.region`
- `AWS_REGION` as a fallback when plugin config does not provide a region

Any agent-supplied `policy_data` is passed through to Rego as `data.*`.

## Data collected

Depending on the selected policy bundles, the plugin can collect and correlate:

- VPCs and VPC attributes
- DHCP options
- subnets
- route tables
- internet gateways
- VPC endpoints
- security groups
- network ACLs
- flow logs
- related CloudWatch log groups
- transit gateway attachments
- network interfaces

## Development

Run the local test suite with:

```shell
go test ./...
```

Or use the Makefile wrapper:

```shell
make test
```

Build the plugin binary with:

```shell
make build
```

This writes the compiled plugin to `dist/plugin`.

## Related repositories

- `../plugin-aws-vpc-policies`
- `../plugin-aws-vpc-subnet-policies`
- `../plugin-aws-vpc-sg-policies`
- `../plugin-aws-vpc-nacl-policies`
- `../plugin-aws-vpc-rt-policies`
