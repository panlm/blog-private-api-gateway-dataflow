---
last_modified: 2023-10-21 11:55:17.321
---

## 私有 API 在企业场景中的应用 - 沿用安全组件

第一个场景我们描述使用 API Gateway 替换现有第三方商用 API Gateway 产品并与现有其他安全设备联动实现安全的应用发布。

### aws blog (released: 2023/05/08)
- https://aws.amazon.com/cn/blogs/china/private-api-gateway-in-enterprise-scenarios/

### github (updated: 2023/10/20)
- [Private API Scenarios in Enterprise Customers（中文版）](TC-private-apigw-dataflow.md)
- [Private API Scenarios in Enterprise Customers （English）](TC-private-apigw-dataflow-en.md)

### appendix
- [Using NGINX simulate WAF to forward HTTPS requests](fake-waf-on-ec2-forwarding-https.md)
- Using this [script](enable-tls-insecure-skip-verification-api-resource-method.md) to enable `tlsConfig/InsecureSkipVerification` for each method and resource in each private API individually


## 私有 API 在企业场景中的应用 - 跨环境访问

第二个场景我们使用 NLB/ALB + API Gateway Endpoint 实现跨环境访问

### aws blog (released: 2023/08/24)
- https://aws.amazon.com/cn/blogs/china/private-api-gateway-in-enterprise-scenarios-2/

### github (updated: 2023/08/10)
- [Using Private API to control cross environment traffic ](TC-private-api-cross-environment-traffic.md)


