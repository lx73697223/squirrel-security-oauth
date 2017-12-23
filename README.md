# Spring OAuth2.0

0. squirrel-oauth-core              oauth公共类

1. squirrel-authorization-service   授权服务

2. squirrel-resource-service-sdk    资源服务SDK

```
资源服务 N->1 授权服务

授权类型: 
    authorization_code：授权码类型。
    implicit：隐式授权类型。
    password：资源所有者（即用户）密码类型。
    client_credentials：客户端凭据（客户端ID以及Key）类型。
    refresh_token：通过以上授权获得的刷新令牌来获取新的令牌。
```

