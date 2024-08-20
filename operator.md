## AWS SageMaker Domain

Amazon SageMaker is a fully managed service that provides every developer and data scientist with the ability to build, train, and deploy machine learning (ML) models quickly. SageMaker removes all the barriers that typically slow down developers who want to use machine learning.

### Design Decisions

- **IAM Role and Policies**: The module includes the creation and association of necessary IAM roles and policies that allow SageMaker to perform required actions (e.g., access to S3, ECR, KMS, CloudWatch).
- **VPC Configuration**: The SageMaker Domain will be attached to a custom VPC and private subnets to enhance security and control over network traffic.
- **KMS Encryption**: An AWS KMS key is used to encrypt data at rest within the SageMaker Domain, ensuring compliance with stringent data security requirements.
- **Security Groups**: The module creates and attaches a security group to the SageMaker Domain to control inbound and outbound traffic.
- **Retention Policy**: Defines a retention policy for the EFS home file system used by SageMaker.

### Runbook

#### SageMaker Domain Not Available

Verify if the SageMaker Domain is available and active.

```sh
aws sagemaker describe-domain --domain-id <domain-id>
```

You should see a status of `InService` for an active SageMaker Domain.

#### Unable to Access SageMaker Studio

Ensure that the user has required permissions and the SageMaker environment is correctly configured.

**Check User Profile**

```sh
aws sagemaker describe-user-profile --domain-id <domain-id> --user-profile-name <user-profile-name>
```

Ensure the user profile status is `InService`.

**Check IAM Role**

Verify that the execution role has the necessary policies attached.

```sh
aws iam list-attached-role-policies --role-name <role-name>
```

Ensure it includes policies like `AmazonSageMakerFullAccess` and other custom policies.

#### Issues with SageMaker Models Accessing S3

Verify the IAM role permissions.

```sh
aws iam get-role-policy --role-name <role-name> --policy-name <policy-name>
```

Ensure that the policy includes permissions for `s3:GetObject` and `s3:ListBucket`.

#### Network Connectivity Problems

Ensure the security group rules allow necessary traffic.

**Check Security Group Rules**

```sh
aws ec2 describe-security-groups --group-ids <security-group-id>
```

Ensure the necessary inbound and outbound rules are configured.

**Verify VPC Subnet Configuration**

```sh
aws ec2 describe-subnets --subnet-ids <subnet-id>
```

Ensure the subnets are within the VPC and have the required route tables and NAT gateways configured if needed for internet access.

#### KMS Key Issues

Ensure the KMS key is active and has the correct policies.

**Check KMS Key Status**

```sh
aws kms describe-key --key-id <key-id>
```

Ensure the key state is `Enabled`.

**Verify Key Policy**

```sh
aws kms get-key-policy --key-id <key-id> --policy-name default
```

Verify that the key policy permits SageMaker access to encrypt and decrypt data.

