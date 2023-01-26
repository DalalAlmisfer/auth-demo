## zitadel integration demo

This demo is an implementation for a self-hosted application that uses an OAuth OIDC protocol with the PKCE authentication method. For more details please read: https://zitadel.com/docs/guides/integrate/login-users

## Pre-requirements
Go to the http://localhost:8080/ui/console and do the following:
 1. Set the identity Provider information in the organization settings
 2. Set the SMTP information in the instance settings

## How to run the app

```
docker compose up --detach

go run main.go
```