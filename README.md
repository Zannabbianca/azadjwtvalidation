[![Go](https://github.com/music-tribe/azadjwtvalidation/actions/workflows/go.yml/badge.svg)](https://github.com/music-tribe/azadjwtvalidation/actions/workflows/go.yml)
[![CodeQL](https://github.com/music-tribe/azadjwtvalidation/actions/workflows/codeql.yml/badge.svg)](https://github.com/music-tribe/azadjwtvalidation/actions/workflows/codeql.yml)
[![codecov](https://codecov.io/gh/music-tribe/azadjwtvalidation/branch/master/graph/badge.svg?token=GCEU8TO2WY)](https://codecov.io/gh/music-tribe/azadjwtvalidation)

# Azure Active Directory JWT validation

> This project is a Traefik plugin based on the work of [dkijkuit](https://github.com/dkijkuit/azurejwttokenvalidation). 

This is a Traefik plugin which validates JWT tokens generated by Azure Active Directory and verifies the claims.

## Supported properties

| Name | Description | Type | Required |
|------|-------------|------|----|
|keysurl | Azure AD Tenant's keys url. |*string*|  yes  |
|issuer | Allowed token issuer. Values for Azure AD and Azure AD B2C are different. |*string*| yes  |
|audience | Allowed audience(s). Audience can either be a single value or a comma separated list of audiences. |*string*| yes  |
|roles | List of roles to be validated by the plugin. |*string[]*| no  |
|matchallroles | Flag to let plugin know if all roles need to be matched to return success. |*boolean*| no  |
|loglevel | Log level for plugin execution. Defaults to *'WARN'* level. <br /><br /> **Possible Values:** INFO, WARN, DEBUG.  |*string*| no  |
|logheaders | If specified, the listed HTTP headers will be added to the logs. Defaults to adding no headers to the logs. <br /><br /> **Security Warning:** Some headers might contain personal or private data. Please choose the data you log carefully or implement mechanisms to make the data available to the correct audience. |*string[]*| no  |

## Example configuration

```yaml
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
    name: azadjwtvalidation
    namespace: traefik
spec:
    plugin:
        azadjwtvalidation:
            keysurl: "https://contoso.b2clogin.com/contoso.onmicrosoft.com/b2c_1_signupsignin1/discovery/v2.0/keys"
            issuer: "https://contoso.b2clogin.com/eecc1921-e709-45c6-b5dc-0a92d28ae4b1/v2.0/"
            audience: "d304eaf9-e22f-48f5-b3cf-c03dcc5452ff,d14ce77d-5be7-437b-b165-16b57813ec4c"
```

## Relevant links

- [jwt.ms](https://jwt.ms/) - validate your Azure AD and Azure AD B2C token online
