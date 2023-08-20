---
title: 私有 API 在企业场景中的应用
description: 私有 API 在企业场景中的应用
chapter: true
created: 2023-03-15 11:49:27.324
last_modified: 2023-05-04 08:48:07.786
tags: 
- aws/serverless/api-gateway 
---

```ad-attention
title: This is a github note

```

# 私有 API 在企业场景中的应用

- [前言](#%E5%89%8D%E8%A8%80)
- [架构描述](#%E6%9E%B6%E6%9E%84%E6%8F%8F%E8%BF%B0)
	- [API Gateway](#api-gateway)
- [搭建实验环境](#%E6%90%AD%E5%BB%BA%E5%AE%9E%E9%AA%8C%E7%8E%AF%E5%A2%83)
	- [环境准备](#%E7%8E%AF%E5%A2%83%E5%87%86%E5%A4%87)
		- [准备 AWS Cloud9 实验环境](#%E5%87%86%E5%A4%87-aws-cloud9-%E5%AE%9E%E9%AA%8C%E7%8E%AF%E5%A2%83)
		- [创建 EKS 集群](#%E5%88%9B%E5%BB%BA-eks-%E9%9B%86%E7%BE%A4)
		- [安装 AWS Load Balancer Controller](#%E5%AE%89%E8%A3%85-aws-load-balancer-controller)
		- [安装 ExternalDNS](#%E5%AE%89%E8%A3%85-externaldns)
		- [设置 Hosted Zone](#%E8%AE%BE%E7%BD%AE-hosted-zone)
		- [创建相关证书](#%E5%88%9B%E5%BB%BA%E7%9B%B8%E5%85%B3%E8%AF%81%E4%B9%A6)
		- [验证环境就绪](#%E9%AA%8C%E8%AF%81%E7%8E%AF%E5%A2%83%E5%B0%B1%E7%BB%AA)
	- [后端应用](#%E5%90%8E%E7%AB%AF%E5%BA%94%E7%94%A8)
	- [API Gateway](#api-gateway)
		- [步骤 1-2 -- External ALB / Route53](#%E6%AD%A5%E9%AA%A4-1-2----external-alb--route53)
		- [步骤 4 -- API Gateway VPCE](#%E6%AD%A5%E9%AA%A4-4----api-gateway-vpce)
		- [步骤 5-7 -- VPC Link](#%E6%AD%A5%E9%AA%A4-5-7----vpc-link)
		- [步骤 9-10 -- Private API / Custom Domain Name / Access Logging](#%E6%AD%A5%E9%AA%A4-9-10----private-api--custom-domain-name--access-logging)
		- [步骤 12 -- 验证](#%E6%AD%A5%E9%AA%A4-12----%E9%AA%8C%E8%AF%81)
- [结论](#%E7%BB%93%E8%AE%BA)
- [参考资料](#%E5%8F%82%E8%80%83%E8%B5%84%E6%96%99)


## 前言

Amazon API Gateway 是亚马逊云科技的一项托管服务，可以帮助开发人员轻松创建、发布、维护、监控和保护任意规模的 API。越来越多的客户在其应用云原生改造中（构建新应用或改造旧应用）使用 Amazon API Gateway 托管服务替换现有应用架构中的第三方 API 网关服务，以实现降低维护管理成本、按需使用提高投入产出比、充分利用云的弹性扩展能力满足业务峰值等价值。使用托管服务并不是简单的替换现有组件，而是需要额外考虑企业已有的安全策略和网络架构等因素，包括：如何保证流量始终保持在 VPC 内部，或者 AWS 的可信网络内部；如何与已有的其他组件交互保证架构的延续性；如何进行访问控制满足企业安全合规要求等。


## 架构描述

在企业用户场景中大量使用第三方安全设备，普遍采用集中式 Ingress 的 ELB Sandwich 架构（详见[博客](https://aws.amazon.com/blogs/networking-and-content-delivery/design-your-firewall-deployment-for-internet-ingress-traffic-flows/)）。我们以此为典型架构，详细分析该架构中使用 Amazon API Gateway 替换第三方 API 网关服务时的数据流。

我们先来看下该架构中使用第三方 API 网关服务时的数据流（下图绿色数字标记）：
- 1： 应用请求将通过外部应用负载均衡（External ALB）， 直接转发到企业内部专有的第三方安全设备，所有流量将经过 7 层的流量过滤和防护 ；
- 2： 经过过滤的流量将转发到第三方 API 网关服务上，然后完成鉴权和请求转发；
- 3： 请求访问到内部应用负载均衡（Internal ALB），最终访问到应用服务；

架构注释：
- 使用独立的 Ingress VPC 可以更好的实现架构扩展性，可以有多个 App VPC 存在，相互独立的同时，附加到 TGW 实现统一的南北向流量管控；
- 扩展到多账号的场景时，可以将 Ingress VPC 置于独立安全账号，将 App VPC  和 API Gateway 等置于应用账号，更清晰的管理权限边界；

![apigw-apigw.drawio.png](apigw-apigw.drawio.png)

Amazon API Gateway 可以直接暴露到公网访问，无需前置任何负载均衡，并且可以使用 AWS 原生的 Web Application Firewall (WAF) 进行过滤和防护，但是本文架构中使用第三方安全设备的原因在于符合公司整体安全策略规范，且可以充分利用已有的安全设备的投资。同时提供更多的优势，包括：实现逐步应用改造、降低管理成本、弹性扩展等。

我们再来分析下使用 Amazon API Gateway 的数据流（上图红色数字标注）：
- 1： 保持对外暴露的架构不变，流量从外部应用负载均衡经过安全设备进行 7 层过滤后访问到 API Gateway 的 VPC Endpoint；
- 2： 请求流量进入 VPC Endpoint 后，将由 API Gateway 进行处理，此时流量虽然已经离开用户的 VPC，但是依然保留在 AWS 可信网络内部；
- 3： 所有请求在转发到下游应用之前需要验证鉴权有效，一般使用 Lambda Authorizer 实现。例如，验证请求中自带的 Access Token 有效；
- 4： 验证鉴权有效之后，请求将通过 VPC Link 访问到客户 VPC 中的应用服务，使用 VPC Link 可以保证请求流量直接进入用户的 VPC 内部而不会传输到公网；
- 5： 由于应用发布在内部应用负载均衡（Internal ALB）上，Rest API 类型的 VPC Link 支持通过内部网络负载均衡（Internal NLB）将请求转发到内部应用负载均衡上，最终访问应用服务；

架构注释：
- 从数据流中可以看出，原有跨 VPC 的数据会经过 Amazon Transit Gateway (TGW)，使用 API Gateway 之后数据将从 AWS 可信网络内部传输，不再需要原有 TGW 组件；
- 与原有架构相比新增了网络负载均衡 ，但是不会对于链路吞吐能力造成瓶颈，因为网络负载均衡属于 4 层协议转发，详见[博客](https://aws.amazon.com/blogs/compute/understanding-vpc-links-in-amazon-api-gateway-private-integrations/)；

本文验证以下内容：
- 使用私有 API Gateway 替代原有第三方 API 网关服务；
- 整个请求链路上使用域名及证书验证有效，且内网服务发布可以使用自签名证书；
- 基于企业安全合规要求，数据流量需要始终保持在客户 VPC 内部以及 AWS 可信网络内部传输，不会意外传输到公网；
- 标头传递到下游应用中使用，以及使用特定标头定制 Access Log
- 实验环境中将跳过 WAF 组件，如果需要参照[这里](fake-waf-on-ec2-forwarding-https.md)配置

### API Gateway

我们梳理下请求经过 API Gateway 过程中需要经过那些组件以及相应的配置细节信息，包括需要绑定的域名以及证书信息，这样会有利于理解。

![apigw-dataflow-png-1.png](apigw-dataflow-png-1.png)

- 1 -  DNS 服务器上，将测试域名 `poc.api0413.aws.panlm.xyz` 解析到外部的 ALB 上；
- 2 - 公有 CA 签发的证书（简称公有证书），配置在外部的 ALB 上，并且指定路径规则将请求进行转发；
- 3 - （可选）此处可以选配安全设备进行 7 层的流量过滤和防护。例如，上一步将请求转发到安全设备特定端口，该端口对应的规则将对所有进入流量进行过滤，然后继续将请求转发到下一步，即 API Gateway 的 VPC Endpoint；
- 4 - 创建 API Gateway 的 VPC Endpoint ，且禁用 `Enable private DNS names`；
- 5 - 创建私有 API ，配置 Resource Policy ，然后部署 API 到 Stage `v1` ，下一步中将使用这个 Stage 名称作为 Mapping 的一部分；
- 6 - 创建定制域名，需要与测试域名 `poc.api0413.aws.panlm.xyz` 一致，且在 ACM 中有该域名的证书。创建 Mapping，将域名映射到特定 Stage 上，如果请求 URL 带有路径信息（ Path Pattern ），则需要填入对应路径信息；
- 7 - 创建 Rest 类型 VPC Link，需要提前创建 NLB 以及 ALB 类型的 Target Group，并将下游应用的 ALB 注册到该 Target Group 上；
- 8 - （可选）使用 Lambda 验证鉴权。一旦鉴权成功，便可从上下文中获取到必要的信息 ([链接](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-mapping-template-reference.html#context-variable-reference:~:text=context.authorizer.property))。比如，使用 Lambda 鉴权请求中自带的 Access Token，成功之后可以从 Access Token 中获取到用户具体详情，作为 header 提供下游应用直接使用；
- 9 - 请求发送到内部应用 ALB 时（确保只使用标准 TLD 域名，参考[链接](https://en.wikipedia.org/wiki/List_of_Internet_top-level_domains)），ALB 使用的证书是自签名证书，且提前导入到 ACM 中（未包含完整证书链），这样的证书使用在 ALB 上是没问题的，但是作为 API Gateway 下游请求的话，则会遇到问题；
	- 首先，API Gateway 默认无法验证自签名证书，除非启用 `tlsConfig/insecureSkipVerification` ([链接](https://aws.amazon.com/premiumsupport/knowledge-center/api-gateway-ssl-certificate-errors/))，且启用后也仅验证包含完整证书链的自签名证书；
	- 其次， 每个 API 的每个 Resource 的每个 Method 都需要单独通过命令行启用，通过这个脚本简化工作 ([链接](http://aws-labs.panlm.xyz/900-others/990-command-line/script-api-resource-method.html))。另外，可以通过导出带 `API Gateway extensions` 的格式修改，并重新导入覆盖；
- 10 - 导入其他需要测试的 API ，提前提升上限 `Resources per API` （默认 300，详见[链接](https://docs.aws.amazon.com/apigateway/latest/developerguide/limits.html)）；
- 11 - 应用 ALB，证书需要满足步骤 9；
- 12 - 验证，通过测试域名 `poc.api0413.aws.panlm.xyz` 直接访问私有 API；


## 搭建实验环境

本文所涉及到的代码可以从 [Github](https://github.com/panlm/blog-private-api-gateway-dataflow) 获取到最新版本。完成本章节后将创建下列资源：
- Ingress VPC - 使用所在区域中的默认 VPC
	- Cloud9 - 交互实验环境
	- Elastic Load Balancer - External ALB 用于接收外部请求
	- VPC Endpoint -  用于私有 API 
- APP VPC - 创建 EKS 集群时自动创建
	- EKS Cluster - 后端应用运行
	- Elastic Load Balancer - Internal ALB 用于应用 Ingress 
	- Elastic Load Balancer - Internal NLB 用于 VPC Link
- 其他资源
	- Private API - 请求将转发到下游 APP VPC 中的应用
	- Route53 Hosted Zone - 实验环境的 DNS
	- Amazon Certificate Manager - 实验环境所需证书 
	- CloudWatch Logs - 用于收集 API Gateway 的 Access Log

### 环境准备

本文使用 AWS Global 的账号，在区域 us-east-2 中搭建。按照下面步骤创建所需的资源。

#### 准备 AWS Cloud9 实验环境 
([链接](http://aws-labs.panlm.xyz/20-cloud9/setup-cloud9-for-eks.html))

-  点击[这里](https://us-east-2.console.aws.amazon.com/cloudshell) 运行 cloudshell，执行代码块创建 cloud9 测试环境 
```sh
# name=<give your cloud9 a name>
datestring=$(date +%Y%m%d-%H%M)
echo ${name:=cloud9-$datestring}

# VPC_ID=<your vpc id> 
# ensure you have public subnet in it
DEFAULT_VPC_ID=$(aws ec2 describe-vpcs \
  --filter Name=is-default,Values=true \
  --query 'Vpcs[0].VpcId' --output text \
  --region ${AWS_DEFAULT_REGION})
VPC_ID=${VPC_ID:=$DEFAULT_VPC_ID}

if [[ ! -z ${VPC_ID} ]]; then
  FIRST_SUBNET=$(aws ec2 describe-subnets \
    --filters "Name=vpc-id,Values=${VPC_ID}" \
    --query 'Subnets[?(AvailabilityZone==`'"${AWS_DEFAULT_REGION}a"'` && MapPublicIpOnLaunch==`true`)].SubnetId' \
    --output text \
    --region ${AWS_DEFAULT_REGION})
  aws cloud9 create-environment-ec2 \
    --name ${name} \
    --image-id amazonlinux-2-x86_64 \
    --instance-type m5.large \
    --subnet-id ${FIRST_SUBNET%% *} \
    --automatic-stop-time-minutes 10080 \
    --region ${AWS_DEFAULT_REGION} |tee /tmp/$$
  echo "Open URL to access your Cloud9 Environment:"
  C9_ID=$(cat /tmp/$$ |jq -r '.environmentId')
  echo "https://${AWS_DEFAULT_REGION}.console.aws.amazon.com/cloud9/ide/${C9_ID}"
else
  echo "you have no default vpc in $AWS_DEFAULT_REGION"
fi

```
- 点击输出的 URL 链接，打开 cloud9 测试环境

- 下面代码块包含一些基本设置，包括：
	- 安装常用的软件
	 - 修改 cloud9 磁盘大小 ([link](https://docs.aws.amazon.com/cloud9/latest/user-guide/move-environment.html#move-environment-resize))
```sh
# set size as your expectation, otherwize 100g as default volume size
# size=200

# install others
sudo yum -y install jq gettext bash-completion moreutils wget

# install awscli
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
echo A |unzip awscliv2.zip
sudo ./aws/install --update
echo "complete -C '/usr/local/bin/aws_completer' aws" >> ~/.bash_profile

# remove existed aws
if [[ $? -eq 0 ]]; then
  sudo yum remove -y awscli
  source ~/.bash_profile
  aws --version
fi

# install ssm session plugin
curl "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/linux_64bit/session-manager-plugin.rpm" -o "session-manager-plugin.rpm"
sudo yum install -y session-manager-plugin.rpm

# your default region 
export AWS_DEFAULT_REGION=$(curl -s 169.254.169.254/latest/dynamic/instance-identity/document | jq -r '.region')

if [[ -c /dev/nvme0 ]]; then
  wget -qO- https://github.com/amazonlinux/amazon-ec2-utils/raw/main/ebsnvme-id >/tmp/ebsnvme-id
  VOLUME_ID=$(sudo python3 /tmp/ebsnvme-id -v /dev/nvme0 |awk '{print $NF}')
  DEVICE_NAME=/dev/nvme0n1
else
  C9_INST_ID=$(curl 169.254.169.254/latest/meta-data/instance-id)
  VOLUME_ID=$(aws ec2 describe-volumes --filters Name=attachment.instance-id,Values=${C9_INST_ID} --query "Volumes[0].VolumeId" --output text)
  DEVICE_NAME=/dev/xvda
fi

aws ec2 modify-volume --volume-id ${VOLUME_ID} --size ${size:-100}
sleep 10
sudo growpart ${DEVICE_NAME} 1
sudo xfs_growfs -d /

if [[ $? -eq 1 ]]; then
  ROOT_PART=$(df |grep -w / |awk '{print $1}')
  sudo resize2fs ${ROOT_PART}
fi

```

- 安装 eks 相关的常用软件 
```sh
# install kubectl with +/- 1 cluster version 1.23.15 / 1.22.17 / 1.24.15 / 1.25.11
# refer: https://kubernetes.io/releases/
# sudo curl --location -o /usr/local/bin/kubectl "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo curl --silent --location -o /usr/local/bin/kubectl "https://storage.googleapis.com/kubernetes-release/release/v1.25.12/bin/linux/amd64/kubectl"
sudo chmod +x /usr/local/bin/kubectl

kubectl completion bash >>  ~/.bash_completion
. /etc/profile.d/bash_completion.sh
. ~/.bash_completion
alias k=kubectl 
complete -F __start_kubectl k
echo "alias k=kubectl" >> ~/.bashrc
echo "complete -F __start_kubectl k" >> ~/.bashrc

# install eksctl
# consider install eksctl version 0.89.0
# if you have older version yaml 
# https://eksctl.io/announcements/nodegroup-override-announcement/
curl --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
sudo mv -v /tmp/eksctl /usr/local/bin
eksctl completion bash >> ~/.bash_completion
. /etc/profile.d/bash_completion.sh
. ~/.bash_completion

# helm newest version (3.10.3)
curl -sSL https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash
# helm 3.8.2 (helm 3.9.0 will have issue #10975)
# wget https://get.helm.sh/helm-v3.8.2-linux-amd64.tar.gz
# tar xf helm-v3.8.2-linux-amd64.tar.gz
# sudo mv linux-amd64/helm /usr/local/bin/helm
helm version --short

# install aws-iam-authenticator 0.5.12 
wget -O aws-iam-authenticator https://github.com/kubernetes-sigs/aws-iam-authenticator/releases/download/v0.5.12/aws-iam-authenticator_0.5.12_linux_amd64
chmod +x ./aws-iam-authenticator
sudo mv ./aws-iam-authenticator /usr/local/bin/

# install kube-no-trouble
sh -c "$(curl -sSL https://git.io/install-kubent)"

# install kubectl convert plugin
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl-convert"
curl -LO "https://dl.k8s.io/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl-convert.sha256"
echo "$(cat kubectl-convert.sha256) kubectl-convert" | sha256sum --check
sudo install -o root -g root -m 0755 kubectl-convert /usr/local/bin/kubectl-convert
rm kubectl-convert kubectl-convert.sha256

# option install jwt-cli
# https://github.com/mike-engel/jwt-cli/blob/main/README.md
# sudo yum -y install cargo
# cargo install jwt-cli
# sudo ln -sf ~/.cargo/bin/jwt /usr/local/bin/jwt

# install flux & fluxctl
curl -s https://fluxcd.io/install.sh | sudo -E bash
flux -v
. <(flux completion bash)

# sudo wget -O /usr/local/bin/fluxctl $(curl https://api.github.com/repos/fluxcd/flux/releases/latest | jq -r ".assets[] | select(.name | test(\"linux_amd64\")) | .browser_download_url")
# sudo chmod 755 /usr/local/bin/fluxctl
# fluxctl version
# fluxctl identity --k8s-fwd-ns flux

```

- 直接执行下面代码块可能遇到权限不够的告警，需要：
	- 如果你有 workshop 的 Credentials ，直接先复制粘贴到命令行，再执行下列步骤；
	- 或者，如果自己账号的 cloud9，先用环境变量方式（`AWS_ACCESS_KEY_ID` 和 `AWS_SECRET_ACCESS_KEY`）保证有足够权限执行 
	- 下面代码块包括：
		- 禁用 cloud9 中的 credential 管理，从 `~/.aws/credentials` 中删除 `aws_session_token=` 行
		- 分配管理员权限 role 到 cloud9 instance
```sh
aws cloud9 update-environment  --environment-id $C9_PID --managed-credentials-action DISABLE
rm -vf ${HOME}/.aws/credentials

# ---
export AWS_PAGER=""
export AWS_DEFAULT_REGION=$(curl -s 169.254.169.254/latest/dynamic/instance-identity/document | jq -r '.region')
C9_INST_ID=$(curl 169.254.169.254/latest/meta-data/instance-id)
ROLE_NAME=adminrole-$RANDOM
MY_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

cat > ec2.json <<-EOF
{
    "Effect": "Allow",
    "Principal": {
        "Service": "ec2.amazonaws.com"
    },
    "Action": "sts:AssumeRole"
}
EOF
STATEMENT_LIST=ec2.json

for i in WSParticipantRole WSOpsRole TeamRole OpsRole ; do
  aws iam get-role --role-name $i >/dev/null 2>&1
  if [[ $? -eq 0 ]]; then
    envsubst >$i.json <<-EOF
{
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::${MY_ACCOUNT_ID}:role/$i"
  },
  "Action": "sts:AssumeRole"
}
EOF
    STATEMENT_LIST=$(echo ${STATEMENT_LIST} "$i.json")
  fi
done

jq -n '{Version: "2012-10-17", Statement: [inputs]}' ${STATEMENT_LIST} > trust.json
echo ${STATEMENT_LIST}
rm -f ${STATEMENT_LIST}

# create role
aws iam create-role --role-name ${ROLE_NAME} \
  --assume-role-policy-document file://trust.json
aws iam attach-role-policy --role-name ${ROLE_NAME} \
  --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"

instance_profile_arn=$(aws ec2 describe-iam-instance-profile-associations \
  --filter Name=instance-id,Values=$C9_INST_ID \
  --query IamInstanceProfileAssociations[0].IamInstanceProfile.Arn \
  --output text)
if [[ ${instance_profile_arn} == "None" ]]; then
  # create one
  aws iam create-instance-profile \
    --instance-profile-name ${ROLE_NAME}
  sleep 10
  # attach role to it
  aws iam add-role-to-instance-profile \
    --instance-profile-name ${ROLE_NAME} \
    --role-name ${ROLE_NAME}
  sleep 10
  # attach instance profile to ec2
  aws ec2 associate-iam-instance-profile \
    --iam-instance-profile Name=${ROLE_NAME} \
    --instance-id ${C9_INST_ID}
else
  existed_role_name=$(aws iam get-instance-profile \
    --instance-profile-name ${instance_profile_arn##*/} \
    --query 'InstanceProfile.Roles[0].RoleName' \
    --output text)
  aws iam attach-role-policy --role-name ${existed_role_name} \
    --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"
fi

```

- 在 cloud9 中，重新打开一个 terminal 窗口，并验证权限符合预期。上面代码块将创建一个 instance profile ，并将关联名为 `adminrole-xxx` 的 role，或者在 cloud9 现有的 role 上关联 `AdministratorAccess` role policy。
```sh
aws sts get-caller-identity
```

#### 创建 EKS 集群
创建 EKS 集群，名为 `ekscluster1` ([链接](http://aws-labs.panlm.xyz/100-eks-infra/110-eks-cluster/eks-public-access-cluster.html#create-eks-cluster))

- 将在下面区域创建 EKS 集群 
```sh
export AWS_PAGER=""
export AWS_DEFAULT_REGION=$(curl -s 169.254.169.254/latest/dynamic/instance-identity/document | jq -r '.region')
export AWS_REGION=${AWS_DEFAULT_REGION}

export CLUSTER_NAME=ekscluster1
export EKS_VERSION=1.25
CLUSTER_NUM=$(eksctl get cluster |wc -l)
export CIDR="10.25${CLUSTER_NUM}.0.0/16"

```

- 执行下面代码创建配置文件
	- 注意集群名称
	- 注意使用的 AZ 符合你所在的区域
```sh
AZS=($(aws ec2 describe-availability-zones \
--query 'AvailabilityZones[].ZoneName' --output text |awk '{print $1,$2}'))
export AZ0=${AZS[0]}
export AZ1=${AZS[1]}

cat >$$.yaml <<-'EOF'
---
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig

metadata:
  name: "${CLUSTER_NAME}"
  region: "${AWS_REGION}"
  version: "${EKS_VERSION}"

availabilityZones: ["${AZ0}", "${AZ1}"]

vpc:
  cidr: "${CIDR}"
  clusterEndpoints:
    privateAccess: true
    publicAccess: true

cloudWatch:
  clusterLogging:
    enableTypes: ["*"]

# secretsEncryption:
#   keyARN: ${MASTER_ARN}

managedNodeGroups:
- name: managed-ng
  minSize: 2
  maxSize: 5
  desiredCapacity: 2
  instanceType: m5.large
  ssh:
    enableSsm: true
  privateNetworking: true

addons:
- name: vpc-cni 
  version: latest
- name: coredns
  version: latest 
- name: kube-proxy
  version: latest

iam:
  withOIDC: true
  serviceAccounts:
  - metadata:
      name: aws-load-balancer-controller
      namespace: kube-system
    wellKnownPolicies:
      awsLoadBalancerController: true
  - metadata:
      name: ebs-csi-controller-sa
      namespace: kube-system
    wellKnownPolicies:
      ebsCSIController: true
  - metadata:
      name: efs-csi-controller-sa
      namespace: kube-system
    wellKnownPolicies:
      efsCSIController: true
  - metadata:
      name: cloudwatch-agent
      namespace: amazon-cloudwatch
    attachPolicyARNs:
    - "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
  - metadata:
      name: fluent-bit
      namespace: amazon-cloudwatch
    attachPolicyARNs:
    - "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
EOF
cat $$.yaml |envsubst '$CLUSTER_NAME $AWS_REGION $AZ0 $AZ1 $EKS_VERSION $CIDR ' > cluster-${CLUSTER_NAME}.yaml

```

- 创建集群，预计需要 20 分钟
```sh
eksctl create cluster -f cluster-${CLUSTER_NAME}.yaml

```

#### 安装 AWS Load Balancer Controller 
([链接](http://aws-labs.panlm.xyz/100-eks-infra/130-eks-network/aws-load-balancer-controller.html#install-))

- Install AWS Load Balancer Controller
```sh
echo ${CLUSTER_NAME}
echo ${AWS_REGION}
echo ${AWS_DEFAULT_REGION}
export AWS_PAGER=""

eksctl utils associate-iam-oidc-provider \
  --cluster ${CLUSTER_NAME} \
  --approve

# curl -o iam_policy.json https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.4.1/docs/install/iam_policy.json
git clone https://github.com/kubernetes-sigs/aws-load-balancer-controller.git

# check iamserviceaccount has been create by eksctl
aws cloudformation describe-stacks --stack-name eksctl-${CLUSTER_NAME}-addon-iamserviceaccount-kube-system-aws-load-balancer-controller 2>&1 1>/dev/null
if [[ $? -ne 0 ]]; then

if [[ ${AWS_REGION%%-*} == "cn" ]]; then 
  # aws china region
  IAM_POLICY_TEMPLATE=iam_policy_cn.json 
else
  # aws commercial region
  IAM_POLICY_TEMPLATE=iam_policy.json 
fi
cp aws-load-balancer-controller/docs/install/${IAM_POLICY_TEMPLATE} .

policy_name=AWSLoadBalancerControllerIAMPolicy-`date +%m%d%H%M`
policy_arn=$(aws iam create-policy \
  --policy-name ${policy_name}  \
  --policy-document file://${IAM_POLICY_TEMPLATE} \
  --query 'Policy.Arn' \
  --output text)

eksctl create iamserviceaccount \
  --cluster=${CLUSTER_NAME} \
  --namespace=kube-system \
  --name=aws-load-balancer-controller \
  --role-name=${policy_name} \
  --attach-policy-arn=${policy_arn} \
  --override-existing-serviceaccounts \
  --approve

# check iamserviceaccount has been create by eksctl
fi

helm repo add eks https://aws.github.io/eks-charts
helm repo update

# following helm cmd will fail if you use 3.9.0 version
# downgrade to helm 3.8.2
# and another solved issue is here: [[ingress-controller-lab-issue]]
if [[ ${AWS_REGION%%-*} == "cn" ]]; then 
  # aws china region
  helm upgrade -i aws-load-balancer-controller eks/aws-load-balancer-controller \
	-n kube-system \
	--set clusterName=${CLUSTER_NAME} \
	--set serviceAccount.create=false \
	--set serviceAccount.name=aws-load-balancer-controller \
	--set image.repository=961992271922.dkr.ecr.cn-northwest-1.amazonaws.com.cn/amazon/aws-load-balancer-controller \
	# --set region=${AWS_DEFAULT_REGION} \
	# --set vpcId=${VPC_ID} 
else
  # aws commercial region
  helm install aws-load-balancer-controller eks/aws-load-balancer-controller \
	-n kube-system \
	--set clusterName=${CLUSTER_NAME} \
	--set serviceAccount.create=false \
	--set serviceAccount.name=aws-load-balancer-controller 
fi

kubectl get deployment -n kube-system aws-load-balancer-controller

```

#### 安装 ExternalDNS 
([链接](http://aws-labs.panlm.xyz/100-eks-infra/130-eks-network/externaldns-for-route53.html#install-))

- 创建所需要的服务账号
	- 确保 EKS 集群名称正确 
	- 确保使用正确的 Region 
	- 确保上游域名已存在，本例中将创建 `api0413.aws.panlm.xyz` 域名，因此确保 `aws.panlm.xyz` 已存在
```sh
echo ${CLUSTER_NAME}
echo ${AWS_REGION}
DOMAIN_NAME=api0413.aws.panlm.xyz
EXTERNALDNS_NS=externaldns
export AWS_PAGER=""

# create namespace if it does not yet exist
kubectl get namespaces | grep -q $EXTERNALDNS_NS || \
  kubectl create namespace $EXTERNALDNS_NS

cat >externaldns-policy.json <<-EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "route53:ChangeResourceRecordSets"
      ],
      "Resource": [
        "arn:aws:route53:::hostedzone/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "route53:ListHostedZones",
        "route53:ListResourceRecordSets"
      ],
      "Resource": [
        "*"
      ]
    }
  ]
}
EOF

POLICY_NAME=AllowExternalDNSUpdates-${RANDOM}
aws iam create-policy --policy-name ${POLICY_NAME} --policy-document file://externaldns-policy.json

# example: arn:aws:iam::XXXXXXXXXXXX:policy/AllowExternalDNSUpdates
export POLICY_ARN=$(aws iam list-policies \
 --query 'Policies[?PolicyName==`'"${POLICY_NAME}"'`].Arn' --output text)

eksctl create iamserviceaccount \
  --cluster ${CLUSTER_NAME} \
  --name "external-dns" \
  --namespace ${EXTERNALDNS_NS:-"default"} \
  --override-existing-serviceaccounts \
  --attach-policy-arn $POLICY_ARN \
  --approve

```

- 使用上述服务账号安装 ExternalDNS 
```sh
echo ${EXTERNALDNS_NS}
echo ${DOMAIN_NAME}
echo ${AWS_REGION}

envsubst >externaldns-with-rbac.yaml <<-EOF
# comment out sa if it was previously created
# apiVersion: v1
# kind: ServiceAccount
# metadata:
#   name: external-dns
#   labels:
#     app.kubernetes.io/name: external-dns
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: external-dns
  labels:
    app.kubernetes.io/name: external-dns
rules:
  - apiGroups: [""]
    resources: ["services","endpoints","pods","nodes"]
    verbs: ["get","watch","list"]
  - apiGroups: ["extensions","networking.k8s.io"]
    resources: ["ingresses"]
    verbs: ["get","watch","list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: external-dns-viewer
  labels:
    app.kubernetes.io/name: external-dns
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: external-dns
subjects:
  - kind: ServiceAccount
    name: external-dns
    namespace: ${EXTERNALDNS_NS} # change to desired namespace: externaldns, kube-addons
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: external-dns
  labels:
    app.kubernetes.io/name: external-dns
spec:
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app.kubernetes.io/name: external-dns
  template:
    metadata:
      labels:
        app.kubernetes.io/name: external-dns
    spec:
      serviceAccountName: external-dns
      containers:
        - name: external-dns
          image: registry.k8s.io/external-dns/external-dns:v0.13.2
          args:
            - --source=service
            - --source=ingress
            - --domain-filter=${DOMAIN_NAME} # will make ExternalDNS see only the hosted zones matching provided domain, omit to process all available hosted zones
            - --provider=aws
            - --policy=upsert-only # would prevent ExternalDNS from deleting any records, omit to enable full synchronization
            - --aws-zone-type=public # only look at public hosted zones (valid values are public, private or no value for both)
            - --registry=txt
            - --txt-owner-id=external-dns
          env:
            - name: AWS_DEFAULT_REGION
              value: ${AWS_REGION} # change to region where EKS is installed
     # # Uncommend below if using static credentials
     #        - name: AWS_SHARED_CREDENTIALS_FILE
     #          value: /.aws/credentials
     #      volumeMounts:
     #        - name: aws-credentials
     #          mountPath: /.aws
     #          readOnly: true
     #  volumes:
     #    - name: aws-credentials
     #      secret:
     #        secretName: external-dns
EOF

kubectl create --filename externaldns-with-rbac.yaml \
  --namespace ${EXTERNALDNS_NS:-"default"}

```

#### 设置 Hosted Zone
首先确保你有自己域名和域名服务器 (Domain Registrar)，然后在当前测试账号的 Route53 下创建 Hosted Zone，并且在上游域名服务器添加该 Hosted Zone 的 NS 记录，以实现二级域名解析 ([链接](http://aws-labs.panlm.xyz/100-eks-infra/130-eks-network/externaldns-for-route53.html#setup-hosted-zone-))

- 本例中将创建 `api0413.aws.panlm.xyz` 域名，因此确保 `aws.panlm.xyz` 已存在
-  执行下面命令创建 Hosted Zone， 然后手工添加 NS 记录到上游的域名服务器 domain registrar 中 
```sh
echo ${DOMAIN_NAME}

aws route53 create-hosted-zone --name "${DOMAIN_NAME}." \
  --caller-reference "external-dns-test-$(date +%s)"

ZONE_ID=$(aws route53 list-hosted-zones-by-name --output json \
  --dns-name "${DOMAIN_NAME}." --query HostedZones[0].Id --out text)

aws route53 list-resource-record-sets --output text \
  --hosted-zone-id $ZONE_ID --query \
  "ResourceRecordSets[?Type == 'NS'].ResourceRecords[*].Value | []" | tr '\t' '\n'

###
# copy above output  
# add NS record on your upstream domain registrar
# set TTL to 172800
###

```

#### 创建相关证书
在 ACM 中创建带有通配符的证书，然后在 Route53 中添加相应的 DNS 记录以验证证书有效性 ([链接](http://aws-labs.panlm.xyz/900-others/990-command-line/acm-cmd.html#create-certificate-))

- 创建并通过添加 dns 记录验证证书 
```sh
echo ${DOMAIN_NAME}
# DOMAIN_NAME=api0413.aws.panlm.xyz

CERTIFICATE_ARN=$(aws acm request-certificate \
--domain-name "*.${DOMAIN_NAME}" \
--validation-method DNS \
--query 'CertificateArn' --output text)

sleep 10
aws acm describe-certificate --certificate-arn ${CERTIFICATE_ARN} |tee /tmp/acm.$$.1
CERT_CNAME_NAME=$(cat /tmp/acm.$$.1 |jq -r '.Certificate.DomainValidationOptions[0].ResourceRecord.Name')
CERT_CNAME_VALUE=$(cat /tmp/acm.$$.1 |jq -r '.Certificate.DomainValidationOptions[0].ResourceRecord.Value')

envsubst >certificate-route53-record.json <<-EOF
{
  "Comment": "UPSERT a record for certificate xxx ",
  "Changes": [
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "${CERT_CNAME_NAME}",
        "Type": "CNAME",
        "TTL": 300,
        "ResourceRecords": [
          {
            "Value": "${CERT_CNAME_VALUE}"
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
aws route53 change-resource-record-sets \
--hosted-zone-id ${ZONE_ID} \
--change-batch file://certificate-route53-record.json 
aws route53 list-resource-record-sets \
--hosted-zone-id ${ZONE_ID} \
--query "ResourceRecordSets[?Name == '${CERT_CNAME_NAME}']"

```

- 等待状态转变成 SUCCESS。如果一直处于 PENDING 状态，请检查 DNS 解析是否成功
```sh
# wait ValidationStatus to SUCCESS
aws acm describe-certificate \
--certificate-arn ${CERTIFICATE_ARN} \
--query 'Certificate.DomainValidationOptions[0]' 

```

#### 验证环境就绪
验证应用发布可用以及证书有效 ([链接](http://aws-labs.panlm.xyz/100-eks-infra/130-eks-network/externaldns-for-route53.html#verify))，如果验证成功，可以从 EKS 集群中删除名为 `verify`  的命名空间

- 创建命名空间 
```sh
NS=verify
kubectl create ns ${NS}
```

- 通过服务定义创建 NLB
```sh
envsubst >verify-nginx.yaml <<-EOF
apiVersion: v1
kind: Service
metadata:
  name: nginx
  annotations:
    external-dns.alpha.kubernetes.io/hostname: nginx.${DOMAIN_NAME}
    service.beta.kubernetes.io/aws-load-balancer-scheme: "internet-facing"
spec:
  type: LoadBalancer
  ports:
  - port: 80
    name: http
    targetPort: 80
  selector:
    app: nginx
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
spec:
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - image: nginx
        name: nginx
        ports:
        - containerPort: 80
          name: http
EOF

kubectl create --filename verify-nginx.yaml -n ${NS:-default}

```

- 等待 NLB 状态可用后执行下面代码块
```sh
aws route53 list-resource-record-sets --output json --hosted-zone-id $ZONE_ID \
  --query "ResourceRecordSets[?Name == 'nginx.${DOMAIN_NAME}.']|[?Type == 'A']"

aws route53 list-resource-record-sets --output json --hosted-zone-id $ZONE_ID \
  --query "ResourceRecordSets[?Name == 'nginx.${DOMAIN_NAME}.']|[?Type == 'TXT']"

dig +short nginx.${DOMAIN_NAME}. A

curl http://nginx.${DOMAIN_NAME}

```

- 确保证书存在，然后创建 ALB 
```sh
echo ${CERTIFICATE_ARN}

envsubst >verify-nginx-ingress.yaml <<-EOF
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: nginx
  annotations:
    alb.ingress.kubernetes.io/scheme: internet-facing
    alb.ingress.kubernetes.io/tags: Environment=dev,Team=test,Application=nginx
    alb.ingress.kubernetes.io/target-type: ip
    alb.ingress.kubernetes.io/listen-ports: '[{"HTTP": 80}, {"HTTPS": 443}]'
    alb.ingress.kubernetes.io/ssl-redirect: '443'
    alb.ingress.kubernetes.io/certificate-arn: ${CERTIFICATE_ARN}
spec:
  ingressClassName: alb
  rules:
    - host: server.${DOMAIN_NAME}
      http:
        paths:
          - backend:
              service:
                name: nginx
                port:
                  number: 80
            path: /
            pathType: Prefix
EOF

kubectl create --filename verify-nginx-ingress.yaml -n ${NS:-default}

```

- 等待 ALB 状态可用后执行下面代码块
```sh
aws route53 list-resource-record-sets --output json --hosted-zone-id $ZONE_ID \
  --query "ResourceRecordSets[?Name == 'server.${DOMAIN_NAME}.']"

dig +short server.${DOMAIN_NAME}. A

curl https://server.${DOMAIN_NAME}

```


### 后端应用

- 使用以下模版配置文件在 EKS 集群中创建 `httpbin` 应用，方便获取到请求中包含的必要信息
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

- 等待 ALB 可用后，验证应用从外部可以正常访问
```sh
curl https://httpbin.${DOMAIN_NAME}/anything
```

- 我们将更新 Ingress 配置，将该 ALB 类型从 Internet-facing 改为 Internal，作为 API Gateway 的下游的 HTTP Endpoint
```sh
sed -i 's/internet-facing/internal/' httpbin.yaml
kubectl apply --filename httpbin.yaml -n httpbin
```

### API Gateway

按照之前描述的内容创建实验环境：

![apigw-dataflow-png-1.png](apigw-dataflow-png-1.png)

#### 步骤 1-2 -- External ALB / Route53

**External ALB**
- 在 Cloud9 所在的 VPC 中，创建外部负载均衡
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
- 创建 CNAME 记录，将测试域名映射到外部负载均衡的默认域名上
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

#### 步骤 4 -- API Gateway VPCE

**API Gateway VPCE**
- 在 Cloud9 所在的 VPC 中，创建 API Gateway 的 VPC Endpoint，这是使用私有 API 的前置条件
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

#### 步骤 5-7 -- VPC Link

**VPC Link**
- 在 EKS 所在的 VPC 中，为应用的内部负载均衡 (Internal ALB) 创建 NLB
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

- 等待 NLB 状态可用后，创建 VPC Link
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

####  步骤 9-10 -- Private API / Custom Domain Name / Access Logging

**API with VPC Link**
![apigw-dataflow-png-2.png](apigw-dataflow-png-2.png)

- 使用下面代码块创建类似上图的 API
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
- 创建定制域名，注意路径与外部应用负载均衡上的转发路径一致
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
API Gateway 中，可以配置两种不同类型日志，API 日志和 Access Log 日志。

- 执行下面代码块创建专用角色，获取 Role ARN，然后将角色添加到 [API Gateway](https://us-east-2.console.aws.amazon.com/apigateway) 的 `Settings` （参考[文档](https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html#set-up-access-logging-using-console)）
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

- 创建专用 CloudWatch 日志组
```sh
LOGGROUP_NAME=apigw-access-log
aws logs create-log-group \
--log-group-name ${LOGGROUP_NAME}
LOGGROUP_ARN=$(aws logs describe-log-groups \
--log-group-name-prefix ${LOGGROUP_NAME} \
--query 'logGroups[0].arn' --output text)
LOGGROUP_ARN=${LOGGROUP_ARN%:*}
```

- 更新现有 API 的 Stage 配置，定制 Access Log 日志输出格式
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

#### 步骤 12 -- 验证

**验证应用可用**
- 从其他设备浏览器访问下面链接时，将请求 API `/httpbin`。该 API 启用 `Use Proxy Integration` 
```sh
echo "curl https://${POC_HOSTNAME}/${URI_PREFIX}/httpbin"
```

![apigw-dataflow-png-3.png](apigw-dataflow-png-3.png)

**查看请求的数据流**
- 从上图 `origin` 字段可以看到完整的请求数据流
	- 第一个地址为客户端地址；
	- 第二个地址为 Cloud9 的 VPC 中，外部负载均衡（External ALB）的内网地址；
	- 第三个地址为 EKS 的 VPC 中，网络负载均衡（NLB）的内网地址；

**自定义标头**
- 从其他设备浏览器访问下面链接时，将请求 API `/httpbin/{proxy+}`。该 API 未启用 `Use Proxy Integration`，原因是我们需要传递自定义标头到下游应用中使用
```sh
echo "curl https://${POC_HOSTNAME}/${URI_PREFIX}/httpbin/anything"
```

![apigw-dataflow-png-4.png](apigw-dataflow-png-4.png)

**查看下游应用可获取到的标头**
- 上图中可以看到，下游应用返回的 `headers` 中包含了我们在 API 中自定义的标头 `xff`，用来获取请求中的 `X-Forwarded-For` 标头。同时可以将这个标头保存到 Access Log 中（如下图），用于安全审计目的；
- 由于我们使用了私有 API，因此 API Gateway 自带的 `$context.identity.sourceIp` 始终为外部应用负载均衡的内网地址（或者 WAF 地址，即进入 Endpoint 前最后一个地址）。通过自定义标头 `xff` 获取更详细的信息；
- 上图 `origin` 为 EKS 的 VPC 中，网络负载均衡（NLB）的内网地址；

![apigw-dataflow-png-5.png](apigw-dataflow-png-5.png)


## 结论

为了替换企业现有应用架构中的第三方 API 网关服务，且满足目前合规性要求，可以使用 Amazon API Gateway 创建私有 API，通过 VPC Endpoint 来保证访问 API 的请求保留在 VPC 内部，使用 VPC Link 功能将请求应用的流量直接导入 VPC 而不会经过公网传输，从而确保安全性。结合企业内部的第三方安全组件时，可以在 VPC Endpoint 之前添加外部应用负载均衡和企业内部的第三方安全设备进行过滤和防护。同时使用统一域名访问，我们会使用自定义域名关联外部应用负载均衡，在 API Gateway 上使用同样的自定义域名作为定制域名关联单个或者多个 API 的 Stage。  
  
这样的架构可以作为目前企业内部使用第三方 API 网关服务的一个替代方案且沿用已有的安全组件。整个请求数据流均在 VPC 内部或者 AWS 可信网络内部，链路上使用域名及证书均可沿用现有配置，且如果内网服务发布使用自签名证书时也可以支持。


## 参考资料

- https://github.com/markilott/aws-cdk-internal-private-api-demo
- https://aws.amazon.com/cn/blogs/china/private-api-integration-across-accounts-and-networks-based-on-amazon-api-gateway/
- https://docs.aws.amazon.com/zh_cn/apigateway/latest/developerguide/apigateway-override-request-response-parameters.html#apigateway-override-request-response-parameters-override-request


