# Spring OAuth2.0

0. squirrel-oauth-core              oauth公共类

1. squirrel-auth-server             授权服务

2. squirrel-resource-service-sdk    资源服务SDK

```
OAuth2中包含四个角色：
    资源拥有者(Resource Owner)
    资源服务器(Resource Server)
    授权服务器(Authorization Server)
    客户端(Client)

资源服务 N->1 授权服务

授权模式:
    authorization_code：授权码类型。
    implicit：隐式授权类型。
    password：资源所有者（即用户）密码类型。
    client_credentials：客户端凭据（客户端ID以及Key）类型。
    refresh_token：通过以上授权获得的刷新令牌来获取新的令牌。

OAuth2的运行流程:
+--------+                               +---------------+
|        |--(A)- Authorization Request ->|   Resource    |
|        |                               |     Owner     |
|        |<-(B)-- Authorization Grant ---|               |
|        |                               +---------------+
|        |
|        |                               +---------------+
|        |--(C)-- Authorization Grant -->| Authorization |
| Client |                               |     Server    |
|        |<-(D)----- Access Token -------|               |
|        |                               +---------------+
|        |
|        |                               +---------------+
|        |--(E)----- Access Token ------>|    Resource   |
|        |                               |     Server    |
|        |<-(F)--- Protected Resource ---|               |
+--------+                               +---------------+



JWT认证协议主体运作流程:
+-----------+                                     +-------------+
|           |       1-Request Authorization       |             |
|           |------------------------------------>|             |
|           |     grant_type&username&password    |             |--+
|           |                                     |Authorization|  | 2-Gen
|           |                                     |Service      |  |   JWT
|           |       3-Response Authorization      |             |<-+
|           |<------------------------------------| Private Key |
|           |    access_token / refresh_token     |             |
|           |    token_type / expire_in           |             |
|  Client   |                                     +-------------+
|           |                                 
|           |                                     +-------------+
|           |       4-Request Resource            |             |
|           |-----------------------------------> |             |
|           | Authorization: bearer Access Token  |             |--+
|           |                                     | Resource    |  | 5-Verify
|           |                                     | Service     |  |  Token
|           |       6-Response Resource           |             |<-+
|           |<----------------------------------- | Public Key  |
+-----------+                                     +-------------+

```
