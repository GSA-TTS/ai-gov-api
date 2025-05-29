# AWS Bedrock Setup Notes

Refer to these notes if you want to set up AWS Bedrock

## Prerequisites

1. **AWS Account**: You need an active AWS account
2. **AWS CLI**: Install the [AWS CLI](https://aws.amazon.com/cli/) if you haven't already:


## Step 1: Enable Model Access in AWS Bedrock

1. **Log into AWS Console**: https://console.aws.amazon.com/

2. **Navigate to Bedrock**:
   - Search for "Bedrock" in the AWS services search bar
   - Click on "Amazon Bedrock"

3. **Select Your Region**:
   - Choose a region that supports Bedrock (e.g., `us-east-1`, `us-west-2`)
   - Note: Not all regions support all models

4. **Request Model Access**:
   - In the left sidebar, click on "Model access"
   - Click "Manage model access" or "Enable models"
   - Select the models you need, for example:
     - **Claude 3.5 Sonnet** (Anthropic)
     - **Llama 3.2 11B** (Meta) or similar Llama model
   - Click "Request model access"
   - Wait for approval (usually immediate for most models, some may take time)

## Step 2: Get Model ARNs

Once models are enabled, you need their ARNs. The ARN format is:
```
arn:aws:bedrock:{region}::foundation-model/{model-id}
```

Common model IDs:
- Claude 3.5 Sonnet: `anthropic.claude-3-5-sonnet-20240620-v1:0`
- Llama 3.2 11B: `meta.llama3-2-11b-instruct-v1:0`
- Cohere Embed English v3: `cohere.embed-english-v3`

So your ARNs would be (replace `{region}` with your region):
```
arn:aws:bedrock:{region}::foundation-model/anthropic.claude-3-5-sonnet-20240620-v1:0
arn:aws:bedrock:{region}::foundation-model/meta.llama3-2-11b-instruct-v1:0
arn:aws:bedrock:{region}::foundation-model/cohere.embed-english-v3
```

At this point, you should be able to construct the ARNs.

## Step 3: Set Up AWS Credentials

### Option A: Using AWS IAM User (Recommended for Development)

1. **Create an IAM User**:
   ```bash
   # If you have AWS CLI configured with admin permissions
   aws iam create-user --user-name bedrock-api-user
   ```

2. **Attach Bedrock Policy**:
   ```bash
   # Create a policy file
   cat > bedrock-policy.json << 'EOF'
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "bedrock:InvokeModel",
           "bedrock:InvokeModelWithResponseStream"
         ],
         "Resource": [
           "arn:aws:bedrock:*::foundation-model/anthropic.claude-3-5-sonnet-*",
           "arn:aws:bedrock:*::foundation-model/meta.llama3-*",
           "arn:aws:bedrock:*::foundation-model/cohere.embed-*"
         ]
       }
     ]
   }
   EOF
   
   # Create the policy
   aws iam create-policy \
     --policy-name BedrockInvokePolicy \
     --policy-document file://bedrock-policy.json
   
   # Attach to user (replace {account-id} with your AWS account ID)
   aws iam attach-user-policy \
     --user-name bedrock-api-user \
     --policy-arn arn:aws:iam::{account-id}:policy/BedrockInvokePolicy
   ```

3. **Create Access Keys**:
   ```bash
   aws iam create-access-key --user-name bedrock-api-user
   ```
   Save the `AccessKeyId` and `SecretAccessKey` from the output.

4. **Configure AWS CLI**:
   ```bash
   aws configure
   ```
   Enter:
   - AWS Access Key ID: [from step 3]
   - AWS Secret Access Key: [from step 3]
   - Default region name: [your chosen region, e.g., us-east-1]
   - Default output format: json

### Option B: Using IAM Role (Recommended for Production)

1. **Create an IAM Role** with Bedrock permissions
2. **Attach the role** to your EC2 instance or use AWS STS for local development

## Step 4: Test Your Setup

Test that you can access Bedrock:

```bash
# List available models
aws bedrock list-foundation-models --region us-east-1

# Test Claude invocation
aws bedrock-runtime invoke-model \
  --model-id anthropic.claude-3-5-sonnet-20240620-v1:0 \
  --body '{"anthropic_version": "bedrock-2023-05-31", "max_tokens": 100, "messages": [{"role": "user", "content": "Hello"}]}' \
  --region us-east-1 \
  output.json
```


## Cost Considerations

AWS Bedrock charges per token for inference:
- **Claude 3.5 Sonnet**: ~$3 per million input tokens, ~$15 per million output tokens
- **Llama models**: Varies by model size
- **Cohere Embed**: ~$0.10 per million tokens

These costs may change.

## Troubleshooting

### "Model not found" Error
- Ensure the model is enabled in your region
- Check that the model ID matches exactly
- Verify your region supports the model

### "Access Denied" Error
- Check IAM permissions include `bedrock:InvokeModel`
- Ensure the resource ARN in the policy matches your models
- Verify AWS credentials are correctly configured

### "Invalid ARN" Error
- Check the ARN format is correct
- Ensure the region in the ARN matches your AWS_DEFAULT_REGION
- Model IDs are case-sensitive

## Security Best Practices

1. **Use IAM Roles** instead of access keys in production
2. **Limit permissions** to only the models you need
3. **Enable CloudTrail** logging for Bedrock API calls
4. **Use AWS Secrets Manager** for storing credentials in production
5. **Set up billing alerts** to monitor costs

## Additional Resources

- [AWS Bedrock Documentation](https://docs.aws.amazon.com/bedrock/)
- [Bedrock Pricing](https://aws.amazon.com/bedrock/pricing/)
- [Model Documentation](https://docs.aws.amazon.com/bedrock/latest/userguide/models-supported.html)