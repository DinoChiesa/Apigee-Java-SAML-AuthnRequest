# Java Callout for SAML AuthnRequest

This directory contains the Java source code and pom.xml file required to
compile a simple Java callout for Apigee, that creates a signed SAML
AuthnRequest, for use in SP-initiated login, with HTTP-POST binding.


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

There is a single jar, apigee-samlauthn-20200710.jar . Within that jar, there is a single callout class,

* com.google.apigee.edgecallouts.samlauthn.Generate - generates a signed SAML AuthnRequest

The Generate callout has these constraints and features:
* supports RSA algorithms - rsa-sha1 (default) or rsa-sha256
* Will automatically add an IssueInstant (timestamp) as an attribute to the AuthnRequest
* signs the entire document, and embeds the Signature element
* uses a canonicalization method of "http://www.w3.org/2001/10/xml-exc-c14n#"
* uses a digest mode of sha1 (default) or sha256
* has various options for embedding the KeyInfo for the certificate in the signed document

## Dependencies

Make sure these JARs are available as resources in the  proxy or in the environment or organization.

* Bouncy Castle: bcprov-jdk15on-1.6x.jar, bcpkix-jdk15on-1.6x.jar

## Usage

### Signing

Configure the policy this way:

```xml
<JavaCallout name='Java-SAMLAuthn-Generate>
  <Properties>
    <Property name='output-variable'>output</Property>
    <Property name='private-key'>{my_private_key}</Property>
    <Property name='certificate'>{my_certificate}</Property>
    <Property name='providerName'>{providerName}</Property>
    <Property name='destination'>{destination}</Property>
    <Property name='issuer'>{issuer}</Property>
    <Property name='acsUrl'>{acsUrl}</Property>
  </Properties>
  <ClassName>com.google.apigee.edgecallouts.samlauthn.Generate</ClassName>
  <ResourceURL>java://apigee-samlauthn-20200710.jar</ResourceURL>
</JavaCallout>
```

The available properties are:

| name                 | description |
| -------------------- | ------------ |
| output-variable      | optional. the variable name in which to write the signed XML. Defaults to message.content |
| private-key          | required. the PEM-encoded RSA private key. You can use a variable reference here as shown above. Probably you want to read this from encrypted KVM. |
| private-key-password | optional. The password for the key, if it is encrypted. |
| key-identifier-type  | optional. One of {`X509_CERT_DIRECT`, or `RSA_KEY_VALUE`}.  See below for details. |
| certificate          | required. The certificate matching the private key. In PEM form. |
| signing-method       | optional. Takes value rsa-sha1 or rsa-sha256. Defaults to rsa-sha1. |
| digest-method        | optional. Takes value sha1 or sha256. Defaults to sha1. |
| provider-name        | required. The name for the Service provider. |
| acs-url              | required. The URL for the AssertionConsumerService. |
| destination          | required. The URL for the Destination. |
| issuer               | required. The URL for the Issuer. |
| name-id-format       | optional. Either 'transient' or 'email'.  Defaults to 'email'. |

This policy will produce a SAML AuthnRequest document and embed a Signature element as a child of the root element.

Regarding `key-identifier-type`, these are the options:

* `x509_cert_direct` gives you this:
  ```xml
  <KeyInfo>
     <X509Data>
       <X509Certificate>MIICAjCCAWu....7BQnulQ=</X509Certificate>
     </X509Data>
   </KeyInfo>
  ```

* `rsa_key_value` gives you this:
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
curl -i https://$ORG-$ENV.apigee.net/samlauthn/generate
```

The result will be something like this:
```
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    AssertionConsumerServiceURL="https://sp.example.com/demo1/index.php?acs"
    Destination="https://idp.example.com/SSOService.php"
    ID="3a48b63b-161d-4a25-b9fa-93892eb4f73a"
    IssueInstant="2020-07-11T00:34:02Z"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    ProviderName="TestServiceProvider" Version="2.0">
  <saml:Issuer>http://sp.example.com/demo1/metadata.php</saml:Issuer>
  <samlp:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/>
  <samlp:RequestedAuthnContext Comparison="exact">
    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
  </samlp:RequestedAuthnContext>
  <Signature
      xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <Reference URI="#3a48b63b-161d-4a25-b9fa-93892eb4f73a">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue>3JymwFs+MvW8AKFNWOyYN1o/a/o=</DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue>pdsgCX6mcA7OpTLp20X/iBvSVqKFWAkHJjkFlUr3PXX0pTPDjXeaIye4d8bRcQgZ8tccjuO3OHqo
    8AFfMAhMHkbTVROeSf98ylfnyER7oKLxIQ4oyyo3j8Y+OS+ezRC5Kti1H0Szxkws7qqXsG+6tHXh
    vQHCS+DRFSXg4u4rjHIKa2dW3TqI0JW3GaPjew5hYluXma4yYnBM6iSgxK4ru12JhKywCq8Jur8P
    GQTVdRZ4C7s6CGlCXCr4P7tAJ0uvrOMskFA3dFrS32KZd/2TZ7oviCMvxSHLUTqosU2isQmFSd6v
    +QuYZQGdWkUUwr5tV4PZDAsG0ipJI8AWAhamyQ==</SignatureValue>
    <KeyInfo>
      <X509Data>
        <X509Certificate>MIIDpDCCAowCCQDsXkZg2rbAwTANBgkqhkiG9w0BAQUFADCBkzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNVBAcMCEtpcmtsYW5kMQ8wDQYDVQQKDAZHb29nbGUxDzANBgNVBAsMBkFwaWdlZTEaMBgGA1UEAwwRYXBpZ2VlLmdvb2dsZS5jb20xHjAcBgkqhkiG9w0BCQEWD2Rpbm9AYXBpZ2VlLmNvbTAeFw0xOTEwMDgxMTExMjBaFw0yOTEwMDUxMTExMjBaMIGTMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjERMA8GA1UEBwwIS2lya2xhbmQxDzANBgNVBAoMBkdvb2dsZTEPMA0GA1UECwwGQXBpZ2VlMRowGAYDVQQDDBFhcGlnZWUuZ29vZ2xlLmNvbTEeMBwGCSqGSIb3DQEJARYPZGlub0BhcGlnZWUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqJA2NwXeqXaVaHO0mkKDpTdhPCh/80gH2Oun4DJOYjYgvdMRJ83xB6Hwm809T593rkX9PwOjUDQ7kJvH0aLaqxb+FrrTDTFcXZXJZ65dca9lYARxgEAwasPIkvBdr0nP2W2VQgPKtkwStZinMiJh/JSlXCz7ULDGVqW8FyklGaVIkxrXhHsjH+hhJ8Kp+zjFsfdsTkGbaqXj/qexeHUBcF6GbHe7xhaLoj/P24D7mFHB3uXx4vN3ohP+ZiT1y5X8fCLVu5SSC+vDFHR2Z5I26yTlcNRwKt24lNypGsEzM5KZILJlEr3BnAA1qkcSX7wZQDHp3XOHJHaR6lxarvYlmQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBD+S4bF8b07955E7HshWFez5Q4/7cXhGPjFaiNw9lH9Ny1iIcblRl36iiVda4Lemy1Kxa5xGJ+I5NZ8k1MyxZ1x5K9bPX5LiI8ThLGRxBNUNLgaoQ+7FZLklpZARoIuQ3Gg90V0qUqkm2eipgZxzdtEGj+lqoX10A2B+wimO6nzUv6vYoJARMBtqsYmQKz5GRBoajGdMn60UF9Ry5B32k31JVpat4qm7+Ig1YMwv2nfY6bgHzsI4WjETOLvFCYgBDJzIEy+0jA1FUe5Ec5Fs5nmiG8F7FRJ/9aYb1e+cbQVRZyc1wKlmIReK/LgG8FjdDjeqFZTg0AjInG8/oOz5ib</X509Certificate>
      </X509Data>
    </KeyInfo>
  </Signature>
</samlp:AuthnRequest>
```


This example has been prettified. The signed document will not be pretty-printed
like that. Applying an XML Digital Signature will collapse whitespace.

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
