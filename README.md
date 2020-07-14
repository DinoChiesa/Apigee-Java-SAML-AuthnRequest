# Java Callout for SAML AuthnRequest

This directory contains the Java source code and pom.xml file required to
compile a simple Java callout for Apigee, that creates a signed SAML
AuthnRequest, for use in SP-initiated login, with HTTP-POST binding or HTTP Redirect binding.

For signature algorithms, it supports `rsa-sha1` and `rsa-sha256`.


## Disclaimer

This example is not an official Google product, nor is it part of an official Google product.

## License

This material is Copyright 2018-2020, Google LLC.
and is licensed under the Apache 2.0 license. See the [LICENSE](LICENSE) file.

This code is open source but you don't need to compile it in order to use it.

## Building

Use maven to build and package the jar. You need maven v3.5 at a minimum.

```
mvn clean package
```

The 'package' goal will copy the jar to the resources/java directory for the
example proxy bundle. If you want to use this in your own API Proxy, you need
to drop this JAR into the appropriate API Proxy bundle. Or include the jar as an
environment-wide or organization-wide jar via the Apigee administrative API.


## Details

There is a single jar, apigee-samlauthn-20200714-1.jar. Within that jar, there is a single callout class,

* com.google.apigee.edgecallouts.samlauthn.Generate - generates a signed SAML AuthnRequest

The Generate callout has these constraints and features:
* supports RSA signing algorithms - `rsa-sha1` (default) or `rsa-sha256`
* uses a digest mode of sha1 (default) or sha256
* Will automatically add an IssueInstant (timestamp) as an attribute to the AuthnRequest
* signs the entire document, and embeds the Signature element
* uses a canonicalization method of "http://www.w3.org/2001/10/xml-exc-c14n#"
* has various options for embedding the KeyInfo for the certificate in the signed document
* various options for including optional elements in the AuthnRequest

## Dependencies

Make sure these JARs are available as resources in the  proxy or in the environment or organization.

* Bouncy Castle: bcprov-jdk15on-1.6x.jar, bcpkix-jdk15on-1.6x.jar

## Usage

### Signing

Here's an example policy configuration:

```xml
<JavaCallout name='Java-SAMLAuthn-Generate>
  <Properties>
    <Property name='output-variable'>output</Property>
    <Property name='private-key'>{my_private_key}</Property>
    <Property name='certificate'>{my_certificate}</Property>
    <Property name='service-provider-name'>{providerName}</Property>
    <Property name='destination'>{destination}</Property>
    <Property name='issuer'>{issuer}</Property>
    <Property name='acs-url'>{acsUrl}</Property>
  </Properties>
  <ClassName>com.google.apigee.edgecallouts.samlauthn.Generate</ClassName>
  <ResourceURL>java://apigee-samlauthn-20200714-1.jar</ResourceURL>
</JavaCallout>
```

This policy will produce a SAML AuthnRequest document and embed a Signature element as a child of the root element.


The available properties are:

| name                  | description  |
| --------------------- | ------------ |
| private-key           | required. the PEM-encoded RSA private key. You can use a variable reference here as shown above. Probably you want to read this from encrypted KVM. |
| certificate           | required. The certificate matching the private key. In PEM form.                          |
| issuer                | required. The URL for the Issuer.                                                         |
| destination           | required. The URL for the Destination.                                                    |
| service-provider-name | required. The name for the Service provider.                                              |
| acs-url               | required. The URL for the AssertionConsumerService.                                       |
| private-key-password  | optional. The password for the key, if it is encrypted.                                   |
| force-authn           | optional. true/false. Defaults false.                                                     |
| key-identifier-type   | optional. One of {`X509_CERT_DIRECT`, or `RSA_KEY_VALUE`}.  See below for details. Applies only to POST `binding-type`. |
| signature-method      | optional. Takes value rsa-sha1 or rsa-sha256. Defaults to rsa-sha1.                       |
| digest-method         | optional. Takes value sha1 or sha256. Defaults to sha1. Aplpies only to POST `binding-type`. |
| requester-id          | optional. the ID for the requester, often a URL. Causes a Scoping element with a RequesterID child to be included in the AuthnRequest. |
| idp-id                | optional. the ID for the IDP, often a URL pointing to metadata. Causes a Scoping element with an IDPList child to be included in the AuthnRequest. |
| idp-location          | optional. the ID for the IDP, often a URL pointing to metadata.                           |
| name-id-format        | optional. Either 'transient' or 'email'.                                                  |
| requested-authn-context | optional.  The only value supported is "password". Causes an RequestedAuthnContext element to be included in the emitted AuthnRequest. |
| binding-type          | optional. Either "Redirect" or "POST". Defaults to "POST"                                 |
| relay-state           | optional. Applies only to `binding-type` of Redirect.                                     |
| url-encode-output     | optional. true/false.  Applies only to Redirect `binding-type`. If true, the policy URL-encodes the various outputs.                     |
| output-variable       | optional. Applies only to POST `binding-type`. Specifies the variable name in which to write the signed XML. Defaults to message.content |

For all properties, the curly braces indicate a reference to a context variable.
You can also omit the curlies to "hard-code" a value.

When the property `binding-type` is `post`, the callout policy will set a single  output variable containing the XML string representing a signed AuthnRequest. You can use the `output-variable` property to affect which variable gets this string.

When the property `binding-type` is `redirect`, the callout policy will set four distinct output variables with strings:
* samlauthn_SAMLRequest
* samlauthn_Signature
* samlauthn_SigAlg
* samlauthn_RelayState


Regarding `key-identifier-type`, these are the options:

* `x509_cert_direct` gives you this in the XML output:
  ```xml
  <KeyInfo>
     <X509Data>
       <X509Certificate>MIICAjCCAWu....7BQnulQ=</X509Certificate>
     </X509Data>
   </KeyInfo>
  ```

* `rsa_key_value` gives you this in the XML output:
  ```xml
  <KeyInfo>
    <KeyValue>
       <RSAKeyValue>
         <Modulus>B6PenDyT58LjZlG6LYD27IFCh1yO+4...yCP9YNDtsLZftMLoQ==</Modulus>
         <Exponent>AQAB</Exponent>
       </RSAKeyValue>
     </KeyValue>
   </KeyInfo>
  ```

## Example API Proxy Bundle

See [the example API proxy included here](./bundle) for a working example of policy configurations.

Deploy the API Proxy to an organization and environment using a tool like [importAndDeploy.js](https://github.com/DinoChiesa/apigee-edge-js/blob/master/examples/importAndDeploy.js)

There are some sample SOAP request documents included in this repo that you can use for demonstrations.

### Invoking the Example proxy

To Generate a signed AuthnRequest:

```
ORG=myorgname
ENV=myenv
curl -i https://$ORG-$ENV.apigee.net/samlauthn/generate1
```

The result will be something like this:
```
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" AssertionConsumerServiceURL="https://sp.example.com/demo1/index.php?acs" Destination="https://idp.example.com/SSOService.php" ID="req-e1cb1e11-b5c8-405b-80a3-792d5cf95253" IssueInstant="2020-07-13T22:30:22Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ProviderName="TestServiceProvider" Version="2.0">
  <saml:Issuer>http://sp.example.com/demo1/metadata.php</saml:Issuer>
  <Signature
      xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <Reference URI="#req-e1cb1e11-b5c8-405b-80a3-792d5cf95253">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue>GAaNDqoETlEZxQKUx627kibxKc8=</DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue>GPuNGs65pJm9rMjBksVw85fTC+STehUAXq8GmyNNzo2VojM9+X84H8FdrQ7KvQhLdYg9QS5SPEkt
    22vPBOVvv11K+Jj0YhsBnD65avjKumo0feR+9sE3WQeWRfUQbnXoyU/FPgMExHzoxMphP9QPC+4S
    +vHisETGke2/t9xtslyXqCr2xBoVaFDiKdVQuOFgQH7Dc7guh00Jbyn++mKhr3KY4r0tlqjcrals
    2oXNfpzNYSwcNJ43GBVQfpWbmQBTCDNw9bLM2MXXxl6DgkVJSSnlGIZQUDXcEu1QzGwAa/sgPlnp
    +lajZ7N6FLUD47iNTLnds88gZdK3BFUr4NZTYg==</SignatureValue>
    <KeyInfo>
      <X509Data>
        <X509Certificate>MIIDpDCCAowCCQDsXkZg2rbAwTANBgkqhkiG9w0BAQUFADCBkzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNVBAcMCEtpcmtsYW5kMQ8wDQYDVQQKDAZHb29nbGUxDzANBgNVBAsMBkFwaWdlZTEaMBgGA1UEAwwRYXBpZ2VlLmdvb2dsZS5jb20xHjAcBgkqhkiG9w0BCQEWD2Rpbm9AYXBpZ2VlLmNvbTAeFw0xOTEwMDgxMTExMjBaFw0yOTEwMDUxMTExMjBaMIGTMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjERMA8GA1UEBwwIS2lya2xhbmQxDzANBgNVBAoMBkdvb2dsZTEPMA0GA1UECwwGQXBpZ2VlMRowGAYDVQQDDBFhcGlnZWUuZ29vZ2xlLmNvbTEeMBwGCSqGSIb3DQEJARYPZGlub0BhcGlnZWUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqJA2NwXeqXaVaHO0mkKDpTdhPCh/80gH2Oun4DJOYjYgvdMRJ83xB6Hwm809T593rkX9PwOjUDQ7kJvH0aLaqxb+FrrTDTFcXZXJZ65dca9lYARxgEAwasPIkvBdr0nP2W2VQgPKtkwStZinMiJh/JSlXCz7ULDGVqW8FyklGaVIkxrXhHsjH+hhJ8Kp+zjFsfdsTkGbaqXj/qexeHUBcF6GbHe7xhaLoj/P24D7mFHB3uXx4vN3ohP+ZiT1y5X8fCLVu5SSC+vDFHR2Z5I26yTlcNRwKt24lNypGsEzM5KZILJlEr3BnAA1qkcSX7wZQDHp3XOHJHaR6lxarvYlmQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBD+S4bF8b07955E7HshWFez5Q4/7cXhGPjFaiNw9lH9Ny1iIcblRl36iiVda4Lemy1Kxa5xGJ+I5NZ8k1MyxZ1x5K9bPX5LiI8ThLGRxBNUNLgaoQ+7FZLklpZARoIuQ3Gg90V0qUqkm2eipgZxzdtEGj+lqoX10A2B+wimO6nzUv6vYoJARMBtqsYmQKz5GRBoajGdMn60UF9Ry5B32k31JVpat4qm7+Ig1YMwv2nfY6bgHzsI4WjETOLvFCYgBDJzIEy+0jA1FUe5Ec5Fs5nmiG8F7FRJ/9aYb1e+cbQVRZyc1wKlmIReK/LgG8FjdDjeqFZTg0AjInG8/oOz5ib</X509Certificate>
      </X509Data>
    </KeyInfo>
  </Signature>
</samlp:AuthnRequest>
```

The following request specifies a Scoping element with the IDP ID and Location.

Invoke:

```
curl -i https://$ORG-$ENV.apigee.net/samlauthn/generate2
```

```
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" AssertionConsumerServiceURL="https://sp.example.com/demo1/index.php?acs" Destination="https://idp.example.com/SSOService.php" ID="req-9a27848c-51cc-4e70-adba-e8812997a525" IssueInstant="2020-07-13T22:29:01Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ProviderName="TestServiceProvider" Version="2.0">
  <saml:Issuer>http://sp.example.com/demo1/metadata.php</saml:Issuer>
  <Signature
      xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <Reference URI="#req-9a27848c-51cc-4e70-adba-e8812997a525">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue>jIaA/2uCpUQ/dNmj/Gt18x5Ynog=</DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue>h8ifwvRAXLDvHxiBQSuu14ovBLPAyEGcTWCy5VmHBSqPjhGbq1w/5yxyMvt5h4i/YRQce1sS7126
    O0IdR8LuEWuSzcTaykYb0mMi8I4pNMZLj73tgz/NcsP8P50QiJ85b9Z6SgF0ZHRHVYuJPNPSRuDJ
    72z+bFATuQixmSEXUoO1tO0DlAwKBc30pwqvZPlNJk/VSf81N3HjXt0x2eYGBWt2OCFp4T63l9pC
    3CHRGyOqp7AbW2bAP362n2ABXR50V59YS33bmV4s0bFQdhCfl+KNZysVRPe43OvSDjhiMAIowHwq
    0vCqDb5gYu5z/z/O6SWymp95Plt6nkfvuULpQw==</SignatureValue>
    <KeyInfo>
      <X509Data>
        <X509Certificate>MIIDpDCCAowCCQDsXkZg2rbAwTANBgkqhkiG9w0BAQUFADCBkzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNVBAcMCEtpcmtsYW5kMQ8wDQYDVQQKDAZHb29nbGUxDzANBgNVBAsMBkFwaWdlZTEaMBgGA1UEAwwRYXBpZ2VlLmdvb2dsZS5jb20xHjAcBgkqhkiG9w0BCQEWD2Rpbm9AYXBpZ2VlLmNvbTAeFw0xOTEwMDgxMTExMjBaFw0yOTEwMDUxMTExMjBaMIGTMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjERMA8GA1UEBwwIS2lya2xhbmQxDzANBgNVBAoMBkdvb2dsZTEPMA0GA1UECwwGQXBpZ2VlMRowGAYDVQQDDBFhcGlnZWUuZ29vZ2xlLmNvbTEeMBwGCSqGSIb3DQEJARYPZGlub0BhcGlnZWUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqJA2NwXeqXaVaHO0mkKDpTdhPCh/80gH2Oun4DJOYjYgvdMRJ83xB6Hwm809T593rkX9PwOjUDQ7kJvH0aLaqxb+FrrTDTFcXZXJZ65dca9lYARxgEAwasPIkvBdr0nP2W2VQgPKtkwStZinMiJh/JSlXCz7ULDGVqW8FyklGaVIkxrXhHsjH+hhJ8Kp+zjFsfdsTkGbaqXj/qexeHUBcF6GbHe7xhaLoj/P24D7mFHB3uXx4vN3ohP+ZiT1y5X8fCLVu5SSC+vDFHR2Z5I26yTlcNRwKt24lNypGsEzM5KZILJlEr3BnAA1qkcSX7wZQDHp3XOHJHaR6lxarvYlmQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBD+S4bF8b07955E7HshWFez5Q4/7cXhGPjFaiNw9lH9Ny1iIcblRl36iiVda4Lemy1Kxa5xGJ+I5NZ8k1MyxZ1x5K9bPX5LiI8ThLGRxBNUNLgaoQ+7FZLklpZARoIuQ3Gg90V0qUqkm2eipgZxzdtEGj+lqoX10A2B+wimO6nzUv6vYoJARMBtqsYmQKz5GRBoajGdMn60UF9Ry5B32k31JVpat4qm7+Ig1YMwv2nfY6bgHzsI4WjETOLvFCYgBDJzIEy+0jA1FUe5Ec5Fs5nmiG8F7FRJ/9aYb1e+cbQVRZyc1wKlmIReK/LgG8FjdDjeqFZTg0AjInG8/oOz5ib</X509Certificate>
      </X509Data>
    </KeyInfo>
  </Signature>
  <samlp:Scoping>
    <samlp:IDPList>
      <samlp:IDPEntry Loc="https://idp.example.com/idp/saml2/sso" ProviderID="https://idp.example.com/idp/saml2/metadata"/>
    </samlp:IDPList>
  </samlp:Scoping>
</samlp:AuthnRequest>
```

Invoke:

```
curl -i https://$ORG-$ENV.apigee.net/samlauthn/generate3
```

```
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" AssertionConsumerServiceURL="https://sp.example.com/demo1/index.php?acs" Destination="https://idp.example.com/SSOService.php" ForceAuthn="true" ID="req-c81b99e3-a11e-47ab-b990-d105db08ec7a" IssueInstant="2020-07-14T16:00:17Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ProviderName="TestServiceProvider" Version="2.0">
  <saml:Issuer>http://sp.example.com/demo1/metadata.php</saml:Issuer>
  <Signature
      xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <Reference URI="#req-c81b99e3-a11e-47ab-b990-d105db08ec7a">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <DigestValue>JoB5QU/gMFsn1kXJLWIb4YQL8UtTFGtTqWs3c+lMRcs=</DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue>Gf2vMlghMmmBGjahAbGA0mnC6/PcbKAMI1lZlnLis5xN0E2yMXpTNjUhHOAnzB2HOrqPO/Ya6eoA
    XJJ//MPrPhONfV2ti6F0jORyw8SUupbuwP9qQA9YgJwpRFLPhDlMLVXMux4jAMMK8T7n3HhZqlw7
    HCedOuTvIYJ7C8Py9OMoNZMwYWFk8QDLgaJFNYZYdsdgy7maLYGio6Vg7zXASammAAN7EKbBHiRd
    aVJqjaRpmO/JiDa7AopGZbnUjZyjsTAzQNl5s1ao29SMEv0Y+KciPS1wqoVU/cuRpf/n8XGxw0DZ
    kK+IsBEiTD/RCz1bUVrUJRRI9XpQ9wHklkLuYA==</SignatureValue>
    <KeyInfo>
      <X509Data>
        <X509Certificate>MIIDpDCCAowCCQDsXkZg2rbAwTANBgkqhkiG9w0BAQUFADCBkzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNVBAcMCEtpcmtsYW5kMQ8wDQYDVQQKDAZHb29nbGUxDzANBgNVBAsMBkFwaWdlZTEaMBgGA1UEAwwRYXBpZ2VlLmdvb2dsZS5jb20xHjAcBgkqhkiG9w0BCQEWD2Rpbm9AYXBpZ2VlLmNvbTAeFw0xOTEwMDgxMTExMjBaFw0yOTEwMDUxMTExMjBaMIGTMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjERMA8GA1UEBwwIS2lya2xhbmQxDzANBgNVBAoMBkdvb2dsZTEPMA0GA1UECwwGQXBpZ2VlMRowGAYDVQQDDBFhcGlnZWUuZ29vZ2xlLmNvbTEeMBwGCSqGSIb3DQEJARYPZGlub0BhcGlnZWUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqJA2NwXeqXaVaHO0mkKDpTdhPCh/80gH2Oun4DJOYjYgvdMRJ83xB6Hwm809T593rkX9PwOjUDQ7kJvH0aLaqxb+FrrTDTFcXZXJZ65dca9lYARxgEAwasPIkvBdr0nP2W2VQgPKtkwStZinMiJh/JSlXCz7ULDGVqW8FyklGaVIkxrXhHsjH+hhJ8Kp+zjFsfdsTkGbaqXj/qexeHUBcF6GbHe7xhaLoj/P24D7mFHB3uXx4vN3ohP+ZiT1y5X8fCLVu5SSC+vDFHR2Z5I26yTlcNRwKt24lNypGsEzM5KZILJlEr3BnAA1qkcSX7wZQDHp3XOHJHaR6lxarvYlmQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBD+S4bF8b07955E7HshWFez5Q4/7cXhGPjFaiNw9lH9Ny1iIcblRl36iiVda4Lemy1Kxa5xGJ+I5NZ8k1MyxZ1x5K9bPX5LiI8ThLGRxBNUNLgaoQ+7FZLklpZARoIuQ3Gg90V0qUqkm2eipgZxzdtEGj+lqoX10A2B+wimO6nzUv6vYoJARMBtqsYmQKz5GRBoajGdMn60UF9Ry5B32k31JVpat4qm7+Ig1YMwv2nfY6bgHzsI4WjETOLvFCYgBDJzIEy+0jA1FUe5Ec5Fs5nmiG8F7FRJ/9aYb1e+cbQVRZyc1wKlmIReK/LgG8FjdDjeqFZTg0AjInG8/oOz5ib</X509Certificate>
      </X509Data>
    </KeyInfo>
  </Signature>
  <samlp:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"/>
  <samlp:Scoping>
    <samlp:RequesterID>https://whatever.example.com/saml/metadata</samlp:RequesterID>
  </samlp:Scoping>
</samlp:AuthnRequest>
```

The responses in these examples have been prettified. The signed document will not be pretty-printed
like that. Applying an XML Digital Signature will canonicalize (c14n), and collapse whitespace.

## Redirect Example

The policy here uses `binding-type` = `redirect`.  This  means the policy will emit the SAML Request and the signature separately.

Invoke:

```
curl -i https://$ORG-$ENV.apigee.net/samlauthn/generate4
```

The output looks like this:

```
SAMLRequest=fVLLbsIwELzzFZbvefFKsUgqWlQViRZE0h56c51NEymxg9ehfH6TQFo4lJu9OzOeHe8ceVlUbFGbTO5gXwMaciwLiaxrBLTWkimOOTLJS0BmBIsWL2s2tF1WaWWUUAW9oNxmcETQJleSkkV/fFQS6xJ0BPqQC3jbrQOaGVMhcxysbDjysirAFqp0EiiV5+QygaNdZdU9F0jJsvGcS95K/RHz5JoZRZuzfkuk5ElpAd3UATW6BkpWy4Bq2FuT9M4H15tanCcja+xBYs1S37NS7gtvnM7uxIQ3aMQaVhINlyagQ3foWq5veeN46LLRlHnuByXbczwPjeFcft1O5vMEQvYcx1tru4niTuCQJ6BfG3RA42bO8wx9g5J30NgN3mjQcEDIvP0E1tnTYZvGfymWYHjCDW/zmDuXrPlpJyKhqsZRfz1vB+jVMuxT/s64gQPoK/kW/qt+Ur5m97X+gUFfuNzC8Ac=

SigAlg=http://www.w3.org/2000/09/xmldsig#rsa-sha1

Signature=HnWqA2H8Rr9IjRqw2NzrU6aVEeLgE/KzGe6Xl3JErliWD6krypaCvJsTtRdHi7BQPOd8wglWvIb1N66401AB2Ndzv6a4uMsGldvIH8Ff39Vxjm7OFFQMdQhcw8gEy7GvGXXETe3yi0UOrFhpLHxdlEWjXylqnBHOOW1ygL7O82YUEc4grzStsYVPqA5BIjlDaWyTxLSNK892YxZ0exK3zNpRj7JYSyda2JDN2CzgRjKuA4OGF48ghMijTAhbGw+FdTceUm6VfqrGGd+zTZcQ2HpaWNIoWeMIh8JlYIbmdfoLJqeVbdZg7BpbdAQZBWhWo+b0vCeVdbnxbu73wkEvAg==

RelayState=rrt-5181747005327207520-b-gwo1-17079-37860156-1
```

Each of those parameters can be used as query parameters in a redirect to the IDP signon URL. Be mindful of URL-encoding the parameter values when constructing the query string.

You can paste these items into [the form here](https://www.samltool.com/validate_authn_req.php) to verify that the signed AuthnRequest is valid.  If you do that you can find the PEM-encoding of the certificate used for this signature in the API Proxy, in [AM-KeyAndCert.xml](./bundle/apiproxy/policies/AM-KeyAndCert.xml).

## About Keys

There is a private RSA key and a corresponding certificate embedded in the API
Proxy. You should not use those for your own purposes. Create your
own. Self-signed is fine for testing purposes. You can
do it with openssl. Creating a privatekey, a certificate signing request, and a
certificate, is as easy as 1, 2, 3:

```
 openssl genpkey  -algorithm rsa -pkeyopt  rsa_keygen_bits:2048 -out privatekey.pem
 openssl req -key privatekey.pem -new -out domain.csr
 openssl x509 -req -days 3650 -in domain.csr -signkey privatekey.pem -out domain.cert
```


## Bugs

none?
