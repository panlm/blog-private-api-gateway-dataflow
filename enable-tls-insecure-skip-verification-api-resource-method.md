---
title: script-api-resource-method
description: 每个 api 的每个 resource 的每个 method 都需要单独通过命令行启用“tlsConfig/insecureSkipVerification”，通过这个脚本简化工作
chapter: true
hidden: false
created: 2023-04-05 21:49:56.309
last_modified: 2023-04-05 21:49:56.309
tags: 
- aws/serverless/api-gateway 
---

```ad-attention
title: This is a github note

```

# script-api-resource-method

每个 api 的每个 resource 的每个 method 都需要单独通过命令行启用“tlsConfig/insecureSkipVerification”，通过这个脚本简化工作

```sh
#!/bin/bash

if [[ $# -ne 1 ]]; then
  echo "$0 API_ID"
  exit 99
fi

export AWS_PAGER=""

API_ID=$1

RESOURCE_FILE=/tmp/${API_ID}.json
aws apigateway get-resources --rest-api-id ${API_ID} >${RESOURCE_FILE}
if [[ $? -ne 0 ]]; then
  echo "api id error"
  exit 99
fi

# get resource ids
RESOURCE_ID=$(cat ${RESOURCE_FILE} |jq -r '.items[].id' |xargs)
for i in ${RESOURCE_ID}; do
  # get method
  METHOD=$(cat ${RESOURCE_FILE} |jq -r '.items[] | select (.id=="'$i'") | .resourceMethods|keys[]' |xargs)
  for j in ${METHOD}; do
    METHOD_FILE=${API_ID}-$i-$j.json
    # save all resource/method json
    aws apigateway get-method --rest-api-id ${API_ID} --resource-id $i --http-method $j > ${METHOD_FILE}
    # if file has specific string, print aws cli to enable tlsConfig
    egrep -ql 'connectionType.*VPC_LINK' ${METHOD_FILE}
    if [[ $? -eq 0 ]]; then
      echo "aws apigateway update-integration --rest-api-id ${API_ID} --resource-id $i --http-method $j --patch-operations \"op='replace',path='/tlsConfig/insecureSkipVerification',value=true\""
    fi
  done
done


```


## refer

https://aws.amazon.com/premiumsupport/knowledge-center/api-gateway-ssl-certificate-errors/



