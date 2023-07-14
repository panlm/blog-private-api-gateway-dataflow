---
title: Private API Scenarios in Enterprise Customers
description: Private API Scenarios in Enterprise Customers
chapter: true
created: 2023-07-12 08:21:49.662
last_modified: 2023-07-12 08:21:49.662
tags: 
- aws/serverless/api-gateway 
---

```ad-attention
title: This is a github note

```

# Private API Scenarios in Enterprise Customers

- [Foreword](#foreword)
- [Architectural description](#architectural-description)
- [Set up your lab environment](#set-up-your-lab-environment)
	- [Prepare Environment](#prepare-environment)
	- [Backend Applications](#backend-applications)
	- [API Gateway](#api-gateway)
		- [Step 1-2](#step-1-2)
		- [Step 4](#step-4)
		- [Step 5-7](#step-5-7)
		- [Step 9-10](#step-9-10)
		- [Step 12](#step-12)
- [Conclusion](#conclusion)
- [References](#references)


## Foreword

Amazon API Gateway is a managed service that helps developers easily create, publish, maintain, monitor, and secure APIs of any scale. More and more customers are using Amazon API Gateway services to replace third-party API gateway products in existed application architectures during their application cloud native transformation (building new applications or transforming old applications) to achieve values such as reducing maintenance costs, using pay-as-you-go to increase the input-output ratio, and making full use of the elastic scalability of the cloud to meet business peaks. Using managed services to replace existing components is not plug and play directly, but requires additional considerations such as the enterprise's existing security policies and network architecture, including how to ensure that traffic always remains within the VPC or within the trusted network of AWS; how to interact with other existing components to ensure the continuity of the architecture; and how to control access to meet enterprise security compliance requirements.

## Architectural description

Third-party security devices are adopted widely in enterprise customers, and the centralized Ingress ELB Sandwich architecture is adopted commonly as well (see [blog](https://aws.amazon.com/blogs/networking-and-content-delivery/design-your-firewall-deployment-for-internet-ingress-traffic-flows/)). In this typical architecture, we deep dive the data flow when using Amazon API Gateway to replace the third-party API gateway products.

Let's first take a look at the data flow when using a third-party API gateway product in this architecture (green numbers in the image below):
- 1: External Application Load Balancer (External ALB), based on the principle of minimum exposure, exposes the APIs that required to be access by external from internet;
- 2: Third-party security equipment, all traffic will go through it for traffic filtering and protection within the enterprise;
- 3: The filtered traffic will be forwarded to a third-party API gateway product, and then complete authentication and authorization, then requests will be keep forwarding;
- 4: Request access to Internal Application Load Balancer (Internal ALB) and access to application finally;

Architectural notes:
- Using an independent Ingress VPC can achieve architectural scalability better. Multiple App VPCs can exist at the same time, and be independent each other, they could be attached to TGW to achieve north-south traffic control;
- When expanding to multi-account scenarios, Ingress VPC can be placed in a separate security account. App VPC and API Gateway can be placed in the application account. it makes management permission boundaries more clear;

![apigw-apigw.drawio.png](apigw-apigw.drawio.png)

Amazon API Gateway could be exposed to Internet directly without any load balancer in front of it, and it could be protected by AWS Web Application Firewall (WAF) for filtering and throttling, but the reason of using third-party security devices in this architecture is that it complies with the company's overall security policy and can make full use existing security equipment without additional investment. It also provides more advantages, including: achieving application transformation gradually, reduced management costs, flexible expansion, etc.

Let's take a look at the data flow when using Amazon API Gateway (marked with red numbers in the image above):
- 1: Keep the external exposure unchanged, the traffic from External ALB is filtered by security equipment, and then access the VPC endpoint of API Gateway;
- 2: After the traffic enters the VPC endpoint, it will be processed by API Gateway. At this time, although the traffic has left the customer's VPC, it remains within the AWS trusted network;
- 3: All requests need to be authenticated and authorized before being forwarded to downstream applications. This is generally achieved using Lambda Authorizer. For example, verify the access token included in the request is valid;
- 4: After authentication and authorization, the request will access the application service in the customer VPC through VPC Link. Using VPC Link can ensure that the traffic enters the user's VPC directly without go through to the Internet;
- 5: The application is published on Internal Application Load Balancer (Internal ALB), the VPC Link for Rest API supports forwarding requests to internal application load balancer through Network Load Balancer (NLB) to access application finally;

Architectural notes:
- We can see, the original cross VPC traffic will pass through the Amazon Transit Gateway (TGW). After using API Gateway, the traffic will be transferred within the AWS trusted network, and the original TGW components will no longer be required;
- Network Load Balancer has been added to the architecture, but it will not become bottlenecks, because Network Load Balancer is a layer 4 forwarding, see [blog](https://aws.amazon.com/blogs/compute/understanding-vpc-links-in-amazon-api-gateway-private-integrations/) for details;

This article verifies the following:
- Use a private type API in Amazon API Gateway to replace the original third-party API Gateway product;
- All certificates is valid in each components on this data flow, and the application services published on Internal ALB can use self-signed certificates;
- Based on corporate security compliance, data traffic needs to always be transmitted within the customer's VPC and within the AWS trusted network without transmission to the Internal accidentally;
- Passing headers to downstream applications for comsumption, and customizing the Access Log with specific headers.

## Set up your lab environment

The latest version of the code covered in this article can be obtained from [Github](https://github.com/panlm/blog-private-api-gateway-dataflow). After completing this section, you will create the following resources:
- Ingress VPC - Use your default VPC in your region
            - Cloud9 - Interactive experimental environment
            - Elastic Load Balancer - External ALB for receiving external requests
            - VPC Endpoint - for private APIs
- App VPC - created automatically when the EKS cluster is created
            - EKS Cluster - Backend application runs on it
            - Elastic Load Balancer - Internal ALB for Ingress
            - Elastic Load Balancer - Internal NLB for VPC Link
- Additional Resources
            - Route53 Hosted Zone - DNS
            - Amazon Certificate Manager - Certificates required in this article
            - CloudWatch Logs - Used to collect API Gateway Access Logs

### Prepare Environment

This article uses an AWS Global account to set up in region us-east-2. Follow these steps to create the relevant resources:
- Interactive environment using AWS Cloud9 as a lab environment ([link](http://aws-labs.panlm.xyz/20-cloud9/setup-cloud9-for-eks.html))
- Create an EKS cluster called `ekscluster1` ([link](http://aws-labs.panlm.xyz/100-eks-infra/110-eks-cluster/eks-public-access-cluster.html#create-eks-cluster))
	- Install the plugin AWS Load Balancer Controller ([link](http://aws-labs.panlm.xyz/100-eks-infra/130-eks-network/aws-load-balancer-controller.html#install -))
	- Install the ExternalDNS plugin ([link](http://aws-labs.panlm.xyz/100-eks-infra/130-eks-network/externaldns-for-route53.html#install -))
- First of all, ensure you have your own domain name and domain registrar. Secondly, create a Hosted Zone under Route53 in current account, and add the NS records of the Hosted Zone to the upstream domain name server to achieve second-level domain name resolution ([link]( http://aws-labs.panlm.xyz/100-eks-infra/130-eks-network/externaldns-for-route53.html#setup-hosted-zone -))
- Create a certificate with wildcard in ACM and add the appropriate DNS records in Route53 to verify the certificate ([link](http://aws-labs.panlm.xyz/900-others/990-command-line/acm-cmd.html#create-certificate -))
- Verify that the application exposed successfully and the certificate is valid ([link](http://aws-labs.panlm.xyz/100-eks-infra/130-eks-network/externaldns-for-route53.html#verify)). After that, you could delete the namespace (`verify`)  in the EKS cluster

### Backend Applications

- Use the following template to create an `httpbin` application in the EKS cluster to obtain the necessary information included in the requests easily
```sh
echo ${CERTIFICATE_ARN}
echo ${DOMAIN_NAME}

kubectl create ns httpbin

envsubst >httpbin.yaml <<-EOF
---
apiVersion: v1
kind: Service
metadata:
  name: httpbin
spec:
  type: NodePort
  ports:
  - port: 80
    name: http
    targetPort: 80
  selector:
    app: httpbin
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: httpbin
spec:
  selector:
    matchLabels:
      app: httpbin
  template:
    metadata:
      labels:
        app: httpbin
    spec:
      containers:
      - image: kennethreitz/httpbin
        name: httpbin
        ports:
        - containerPort: 80
          name: http
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: httpbin
  annotations:
    alb.ingress.kubernetes.io/scheme: internet-facing
    alb.ingress.kubernetes.io/tags: Environment=dev,Team=test,Application=httpbin
    alb.ingress.kubernetes.io/target-type: ip
    alb.ingress.kubernetes.io/listen-ports: '[{"HTTP": 80}, {"HTTPS": 443}]'
    alb.ingress.kubernetes.io/ssl-redirect: '443'
    alb.ingress.kubernetes.io/certificate-arn: ${CERTIFICATE_ARN}
    alb.ingress.kubernetes.io/group.name: intalb
    alb.ingress.kubernetes.io/group.order: '99'
spec:
  ingressClassName: alb
  rules:
    - host: httpbin.${DOMAIN_NAME}
      http:
        paths:
          - backend:
              service:
                name: httpbin
                port:
                  number: 80
            path: /
            pathType: Prefix
EOF

kubectl create --filename httpbin.yaml -n httpbin
```

- Wait for ALB to be available and verify that the app is accessible from the Internet directly
```sh
curl https://httpbin.${DOMAIN_NAME}/anything
```

- Let's update the Ingress yaml file and change the ALB type from Internet-facing to Internal. make it as the downstream HTTP endpoint of private API
```sh
sed -i 's/internet-facing/internal/' httpbin.yaml
kubectl apply --filename httpbin.yaml -n httpbin
```

### API Gateway

Let's go through the components and configuration details when the requests processed by Amazon API Gateway, including the domain name and certificates, it will be easier for your to understand well.

![apigw-dataflow-png-1.png](apigw-dataflow-png-1.png)

- 1 - On the DNS server, resolve the test domain name `poc.xxx.com` to the External ALB;
- 2 - Put a certificate issued by a public CA (public certificate for short) on the External ALB and specified path rules for requests forwarding;
- 3 - (Optional) Here, security devices can be equipped for traffic protection. For example, the previous step forwards the request to the specific port of the security appliance, and the rules corresponding to that port will filter all incoming traffic, then continue forwarding the request to the next step, which is API Gateway's VPC Endpoint;
- 4 - Create a VPC endpoint for API Gateway and disable `Enable private DNS names`;
- 5 - Create a private API, configure a resource policy, then deploy the API to stage `v1`. The stage name will be used as part of the mapping in the next step;
- 6 - To create a custom domain name, you need to match the test domain name `poc.xxx.com` and have a certificate for that domain name in ACM. Create mapping and map the domain name to a specific stage. If the request URL has path pattern, you need to fill in as well;
- 7 - To create a Rest type VPC Link, you need to create an NLB and an ALB type Target Group in advance, and register the ALB of the downstream application to this Target Group;
- 8 - (Optional) Using Lambda authorizer. Once the authentication is successful, the necessary information can be obtained from the context ([link](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-mapping-template-reference.html#context-variable-reference:~:text = context.authorizer.property)). For example, using the Access Token that comes with the Lambda authentication request, after success, the user's specific details can be obtained from the Access Token and provided as a header for direct use by downstream applications;
- 9 - When request is sent to the Internal ALB, the certificate on Internal ALB is a self-signed certificate and imported into ACM in advance (without full certificate chain in ACM). There is no problem using such certificate on ALB, but if request comes from API Gateway, problems occurs;
	- First, API Gateway cannot verify self-signed certificates by default unless `tlsConfig/InsecureSkipVerification` is enabled ([link](https://aws.amazon.com/premiumsupport/knowledge-center/api-gateway-ssl-certificate-errors/)). Certificates will be verified successfully only when it includes full certificate chain in ACM.
	- Second, each method and resource in each private API needs to be enabled individually via the command line, making work easier through this script ([link](http://aws-labs.panlm.xyz/900-others/990-command-line/script-api-resource-method.html)). Also, the format can be modified by exporting `API Gateway extensions` and re-importing the coverage;
- 10 - Import other APIs that need to be tested and don't forgot to raise the limit of `Resources per API` in advance (default 300, see [link](https://docs.aws.amazon.com/apigateway/latest/developerguide/limits.html) for details);
- 11 - To Internal ALB, the certificate must meet requirements in step 9;
- 12 - Verification, direct access to the private API through the test domain name `poc.xxx.com`;

#### Step 1-2

**External ALB**
- Create an External ALB in the VPC where Cloud9 is located in.
```sh
UNIQ_STR=$RANDOM
PORT443=443
POC_HOSTNAME=poc.${DOMAIN_NAME}
URI_PREFIX=uri-prefix

echo ${CERTIFICATE_ARN}
echo ${CLUSTER_NAME}
echo ${AWS_DEFAULT_REGION}

# get cloud9 vpc
C9_INST_ID=$(curl http://169.254.169.254/1.0/meta-data/instance-id 2>/dev/null)
C9_VPC_ID=$(aws ec2 describe-instances \
--instance-ids ${C9_INST_ID} \
--query 'Reservations[0].Instances[0].VpcId' --output text)

# get public subnet for external alb
C9_SUBNETS_ID=$(aws ec2 describe-subnets \
--filter "Name=vpc-id,Values=${C9_VPC_ID}" \
--query 'Subnets[?MapPublicIpOnLaunch==`true`].SubnetId' \
--output text)

# get default security group 
C9_DEFAULT_SG_ID=$(aws ec2 describe-security-groups \
--filter Name=vpc-id,Values=${C9_VPC_ID} \
--query "SecurityGroups[?GroupName == 'default'].GroupId" \
--output text)

# allow 80/443 from anywhere
for i in 80 443 ; do
aws ec2 authorize-security-group-ingress \
  --group-id ${C9_DEFAULT_SG_ID} \
  --protocol tcp \
  --port $i \
  --cidr 0.0.0.0/0  
done

# create external alb
aws elbv2 create-load-balancer --name ext-alb-${UNIQ_STR} \
--subnets ${C9_SUBNETS_ID} \
--security-groups ${C9_DEFAULT_SG_ID} |tee /tmp/$$.1
alb1_arn=$(cat /tmp/$$.1 |jq -r '.LoadBalancers[0].LoadBalancerArn')
alb1_dnsname=$(cat /tmp/$$.1 |jq -r '.LoadBalancers[0].DNSName')

aws elbv2 create-target-group \
--name ext-alb-tg-${PORT443}-${UNIQ_STR} \
--protocol HTTPS \
--port ${PORT443} \
--target-type ip \
--vpc-id ${C9_VPC_ID} \
--matcher HttpCode="200-202\,400-404" |tee /tmp/$$.2
tg1_arn=$(cat /tmp/$$.2 |jq -r '.TargetGroups[0].TargetGroupArn')

aws elbv2 create-listener --load-balancer-arn ${alb1_arn} \
--protocol HTTPS --port ${PORT443}  \
--certificates CertificateArn=${CERTIFICATE_ARN} \
--default-actions Type=fixed-response,FixedResponseConfig="{MessageBody=,StatusCode=404,ContentType=text/plain}" |tee /tmp/$$.2.1
listener_arn=$(cat /tmp/$$.2.1 |jq -r '.Listeners[0].ListenerArn')

# rules with path pattern in listener 
envsubst >/tmp/path-pattern.json <<-EOF
[
    {
        "Field": "path-pattern",
        "PathPatternConfig": {
            "Values": ["/${URI_PREFIX}/*"]
        }
    }
]
EOF

aws elbv2 create-rule --listener-arn ${listener_arn} \
--conditions file:///tmp/path-pattern.json \
--priority 5 \
--actions Type=forward,TargetGroupArn=${tg1_arn}
```

**Route53**
- Create a CNAME record to map the test domain name to the default domain name of External ALB
```sh
echo ${POC_HOSTNAME}
echo ${alb1_dnsname}

envsubst >poc-route53-record.json <<-EOF
{
  "Comment": "UPSERT a record for poc.xxx.com ",
  "Changes": [
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "${POC_HOSTNAME}",
        "Type": "CNAME",
        "TTL": 300,
        "ResourceRecords": [
          {
            "Value": "${alb1_dnsname}"
          }
        ]
      }
    }
  ]
}
EOF

ZONE_ID=$(aws route53 list-hosted-zones-by-name \
--dns-name "${DOMAIN_NAME}." \
--query HostedZones[0].Id --output text)

aws route53 change-resource-record-sets --hosted-zone-id ${ZONE_ID} --change-batch file://poc-route53-record.json

aws route53 list-resource-record-sets --hosted-zone-id ${ZONE_ID} --query "ResourceRecordSets[?Name == '${POC_HOSTNAME}.']"
```

#### Step 4

**API Gateway VPCE**
- In the VPC where Cloud9 is located in, create a VPC endpoint for API Gateway. This is a prerequisite for using a private API
```sh
echo ${C9_VPC_ID}
echo ${C9_SUBNETS_ID}
echo ${C9_DEFAULT_SG_ID}

aws ec2 create-vpc-endpoint \
--vpc-id ${C9_VPC_ID} \
--vpc-endpoint-type Interface \
--service-name com.amazonaws.${AWS_DEFAULT_REGION}.execute-api \
--subnet-ids ${C9_SUBNETS_ID} \
--security-group-id ${C9_DEFAULT_SG_ID} \
--no-private-dns-enabled |tee /tmp/$$.3
ENDPOINT_ID=$(cat /tmp/$$.3 |jq -r '.VpcEndpoint.VpcEndpointId')
ENDPOINT_ENI=$(cat /tmp/$$.3 |jq -r '.VpcEndpoint.NetworkInterfaceIds[]' |xargs )

# wait until available
watch -g -n 10 aws ec2 describe-vpc-endpoints \
--vpc-endpoint-ids ${ENDPOINT_ID} \
--query 'VpcEndpoints[0].State'

# get endpoint ip address
ENDPOINT_ENI_IP=$(aws ec2 describe-network-interfaces --network-interface-ids ${ENDPOINT_ENI} --query 'NetworkInterfaces[].PrivateIpAddress' --output text)

# add ip address to alb's target group
targets=$(for i in ${ENDPOINT_ENI_IP} ; do
  echo "Id=$i"
done |xargs )

aws elbv2 register-targets \
--target-group-arn ${tg1_arn} \
--targets ${targets}
```

#### Step 5-7

**VPC Link**
- In the VPC where EKS is located in, create an NLB for the application's Internal ALB
```sh
# get eks vpc id
EKS_VPC_ID=$(aws eks describe-cluster \
--name ${CLUSTER_NAME} \
--query "cluster.resourcesVpcConfig.vpcId" --output text )

EKS_PRIV_SUBNETS_ID=$(aws ec2 describe-subnets \
--filter "Name=vpc-id,Values=${EKS_VPC_ID}" \
--query 'Subnets[?MapPublicIpOnLaunch==`false`].SubnetId' \
--output text)

INT_ALB_DNS_NAME=$(kubectl get ing httpbin -n httpbin --output json  |jq -r '.status.loadBalancer.ingress[].hostname' )

INT_ALB_ARN=$(aws elbv2 describe-load-balancers --query "LoadBalancers[?DNSName=='${INT_ALB_DNS_NAME}'][].LoadBalancerArn" --output text)

# create alb-type target group
aws elbv2 create-target-group \
--name int-nlb-tg-alb-${UNIQ_STR} \
--protocol TCP \
--port ${PORT443} \
--target-type alb \
--vpc-id ${EKS_VPC_ID} |tee /tmp/$$.4
tg2_arn=$(cat /tmp/$$.4 |jq -r '.TargetGroups[0].TargetGroupArn')

# register alb to tg
# will failed, if your alb status is not active
aws elbv2 register-targets \
--target-group-arn ${tg2_arn} \
--targets Id=${INT_ALB_ARN}

# create nlb
aws elbv2 create-load-balancer \
--name int-nlb-${UNIQ_STR} \
--type network \
--scheme internal \
--subnets ${EKS_PRIV_SUBNETS_ID} |tee /tmp/$$.5
nlb1_arn=$(cat /tmp/$$.5 |jq -r '.LoadBalancers[0].LoadBalancerArn')

# create listener for nlb
aws elbv2 create-listener --load-balancer-arn ${nlb1_arn} \
--protocol TCP --port ${PORT443}  \
--default-actions Type=forward,TargetGroupArn=${tg2_arn}

# wait until active
watch -g -n 60 aws elbv2 describe-load-balancers \
--load-balancer-arns ${nlb1_arn} \
--query 'LoadBalancers[0].State'
```

- Wait for the NLB status to be available, then create a VPC Link
```sh
# create vpc link
aws apigateway create-vpc-link --name vpclink-rest \
--target-arns ${nlb1_arn} |tee /tmp/$$.6
VPCLINK_ID=$(cat /tmp/$$.6 |jq -r '.id')

# wait about 10 mins until AVAILABLE
watch -g -n 60 aws apigateway get-vpc-link \
--vpc-link-id ${VPCLINK_ID} \
--query 'status'
```

#### Step 9-10

**API with VPC Link**

![apigw-dataflow-png-2.png](apigw-dataflow-png-2.png)

- Use the following code block to create an API similar to the screenshot above
```sh
API_NAME=MyAPI-${UNIQ_STR}
echo ${API_NAME}
echo ${VPCLINK_ID}
echo ${ENDPOINT_ID}
echo ${DOMAIN_NAME}

envsubst >api-definition.yml <<-EOF
---
swagger: "2.0"
info:
  version: "2023-04-10T06:38:46Z"
  title: "${API_NAME}"
basePath: "/uri-prefix"
schemes:
- "https"
paths:
  /httpbin:
    get:
      responses: {}
      x-amazon-apigateway-integration:
        connectionId: "${VPCLINK_ID}"
        httpMethod: "GET"
        uri: "https://httpbin.${DOMAIN_NAME}/anything"
        responses:
          default:
            statusCode: "200"
        passthroughBehavior: "when_no_match"
        connectionType: "VPC_LINK"
        tlsConfig:
          insecureSkipVerification: true
        type: "http_proxy"
  /httpbin/{proxy+}:
    x-amazon-apigateway-any-method:
      consumes:
      - "application/json"
      parameters:
      - name: "xff"
        in: "header"
        required: false
        type: "string"
      - name: "proxy"
        in: "path"
        required: true
        type: "string"
      responses: 
        "200":
          description: "200 response"
      x-amazon-apigateway-integration:
        connectionId: "${VPCLINK_ID}"
        httpMethod: "ANY"
        uri: "https://httpbin.${DOMAIN_NAME}/{proxy}"
        responses:
          default:
            statusCode: "200"
        requestParameters:
          integration.request.path.proxy: "method.request.path.proxy"
          integration.request.header.xff: "method.request.header.xff"
        passthroughBehavior: "when_no_templates"
        connectionType: "VPC_LINK"
        type: "http"
#        cacheNamespace: "bv1a7a"
#        cacheKeyParameters:
#        - "method.request.path.proxy"
EOF

cat >api-definition-template.yml <<-'EOF'
        requestTemplates:
          application/json: |
            #set($xffValue = "$input.params('X-Forwarded-For')")
            $input.json("$")
            #set($context.requestOverride.header.xff = $xffValue)
EOF

envsubst >api-definition-policy.yml <<-EOF
x-amazon-apigateway-policy:
  Version: "2012-10-17"
  Statement:
  - Effect: "Deny"
    Principal: "*"
    Action: "execute-api:Invoke"
    Resource: "execute-api:/*/*/*"
    Condition:
      StringNotEquals:
        aws:sourceVpce: 
        - "${ENDPOINT_ID}"
  - Effect: "Allow"
    Principal: "*"
    Action: "execute-api:Invoke"
    Resource: "execute-api:/*/*/*"
EOF

cat api-definition.yml api-definition-template.yml api-definition-policy.yml >api-definition-full.yml

aws apigateway import-rest-api \
--parameters endpointConfigurationTypes=PRIVATE \
--body fileb://api-definition-full.yml |tee /tmp/$$.7
API_ID=$(cat /tmp/$$.7 |jq -r '.id')

aws apigateway create-deployment \
--rest-api-id ${API_ID} --stage-name v1 
```

**Custom Domain Name**
- Create a custom domain name, and note that the path is consistent with the forwarding path on the External ALB
```sh
echo ${CERTIFICATE_ARN}
echo ${POC_HOSTNAME}
echo ${URI_PREFIX}

aws apigateway create-domain-name \
--domain-name ${POC_HOSTNAME} \
--endpoint-configuration types=REGIONAL \
--regional-certificate-arn ${CERTIFICATE_ARN} 

aws apigateway create-base-path-mapping \
--domain-name ${POC_HOSTNAME} \
--rest-api-id ${API_ID} \
--stage v1 \
--base-path "${URI_PREFIX}"
```

**Custom Access Logging**
In API Gateway, you can configure two different types of logs, API logs and access log logs.

- Execute the following code block to create a dedicated role, get the Role ARN, and add the role to 'Settings' (see [Documentation](https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html#set-up-access-logging-using-console))
```sh
ROLE_NAME=apigatewayrole-$(date +%Y%m%d-%H%M)
echo '{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
                "Service": [
                    "apigateway.amazonaws.com"
                ]
            },
            "Action": [
                "sts:AssumeRole"
            ]
        }
    ]
}' |tee role-trust-policy.json
aws iam create-role --role-name ${ROLE_NAME} \
  --assume-role-policy-document file://role-trust-policy.json
aws iam attach-role-policy --role-name ${ROLE_NAME} \
  --policy-arn "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
aws iam list-attached-role-policies --role-name ${ROLE_NAME}

role_arn=$(aws iam get-role --role-name ${ROLE_NAME} |jq -r '.Role.Arn')

echo ${role_arn}

###
# copy above output
# add role to api gateway settings
###
```

- Create a dedicated CloudWatch log group
```sh
LOGGROUP_NAME=apigw-access-log
aws logs create-log-group \
--log-group-name ${LOGGROUP_NAME}
LOGGROUP_ARN=$(aws logs describe-log-groups \
--log-group-name-prefix ${LOGGROUP_NAME} \
--query 'logGroups[0].arn' --output text)
LOGGROUP_ARN=${LOGGROUP_ARN%:*}
```

- Update the configuration of stage, and customize the Access Log log output format
```sh
echo ${API_ID}
echo ${LOGGROUP_ARN}

echo '{ 
	"requestId": "$context.requestId", 
	"caller": "$context.identity.caller", 
	"user": "$context.identity.user",
	"requestTime": "$context.requestTime", 
	"httpMethod": "$context.httpMethod",
	"resourcePath": "$context.resourcePath", 
	"status": "$context.status",
	"protocol": "$context.protocol", 
	"responseLength": "$context.responseLength",
	"ip": "$context.identity.sourceIp", 
	"xff": "$context.requestOverride.header.xff"
}' |tee access-log-format.json

format_str=$(cat access-log-format.json |sed 's/"/\\"/g' |xargs |sed 's/"/\\"/g')

echo '{"patchOperations": []}' |\
jq '.patchOperations[0] = {"op": "replace", "path": "/accessLogSettings/format", "value": "'"${format_str}"'"}' |\
jq '.patchOperations[1] = {"op": "replace", "path": "/accessLogSettings/destinationArn", "value": "'"${LOGGROUP_ARN}"'"}' |tee access-log-settings.json

aws apigateway update-stage \
--rest-api-id $API_ID \
--stage-name v1 \
--cli-input-json file://access-log-settings.json
```

#### Step 12

**Verify application is accessable**
- Access the link below from another device's browser, it will request `/httpbin` resource in API definition. We have enabled `Use Proxy Integration` in API. 
```sh
echo "curl https://${POC_HOSTNAME}/${URI_PREFIX}/httpbin"
```

![apigw-dataflow-png-3.png](apigw-dataflow-png-3.png)

**check the request's detail**
- You can see all components the request go through in the `origin` field in the image above
	- The first IP address is the client address;
	- The second IP address is the internal IP address of the External ALB in the VPC of Cloud9;
	- The third IP address is the internal IP address of the NLB in the EKS VPC;

**Custom header**
- Access the link below from another device's browser, it will request `/httpbin/{proxy+}` resource in API definition. we do not enable `Use Proxy Integration` in API. The reason is we need to forward custom headers to downstream applications. 
```sh
echo "curl https://${POC_HOSTNAME}/${URI_PREFIX}/httpbin/anything"
```

![apigw-dataflow-png-4.png](apigw-dataflow-png-4.png)

**Check the headers available in downstream applications**
- As you can see in the image above, the headers returned by the downstream application include the header `xff` that we customized in the API to obtain the `X-Forwarded-For` header in the request. At the same time, this header can be saved to the Access Log (as shown below) for security audit purposes;
- Since we use a private API, the `$context.identity.sourceIp` that comes with API Gateway is always the internal IP address for External ALB. Get more detailed information through this custom header `xff`;

![apigw-dataflow-png-5.png](apigw-dataflow-png-5.png)

## Conclusion

In order to replace the third-party API gateway service in the enterprise's existing application architecture and meet current compliance requirements, you can use Amazon API Gateway to create a private API, use the VPC Endpoint to ensure that requests to access the API remain within the VPC, and use the VPC Link to forward requests into the VPC directly without transmission over Internet to ensure security. When works with third-party security components in the enterprise, External ALB and internal third-party security devices can be added for filtering and protection before the VPC endpoint of API Gateway. 

Such an architecture can be used as an alternative to the current use of third-party API gateway services within the enterprise and continue to use existing security components. The entire request data flow is within the VPC or within the AWS trusted network. Using domain names and certificates on the link can continue with the existing configuration, and can also be supported if the application published with a self-signed certificate.

## References

- https://github.com/markilott/aws-cdk-internal-private-api-demo
- https://aws.amazon.com/cn/blogs/china/private-api-integration-across-accounts-and-networks-based-on-amazon-api-gateway/
- https://docs.aws.amazon.com/zh_cn/apigateway/latest/developerguide/apigateway-override-request-response-parameters.html#apigateway-override-request-response-parameters-override-request




