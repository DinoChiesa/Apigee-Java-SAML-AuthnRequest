package com.google.apigee.callouts.samlauthn;

import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

public class SignConfiguration {
  // required
  public RSAPrivateKey privatekey;
  public X509Certificate certificate;
  public String destination;
  public String serviceProviderName; // should this be optional?
  public String acsUrl;
  public String issuer;
  // optional
  public boolean forceAuthn;
  public boolean urlEncodeOutput;
  public String subject; // not recommended for SAML2
  public String nameIdFormat;
  public String relayState; // for HTTP Redirect only
  public String requestedAuthnContext;
  public String idpId, idpLocation; // under scoping
  public String requesterId; // under scoping
  public String signingMethod;
  public String digestMethod;
  public KeyIdentifierType keyIdentifierType;
  public BindingType bindingType;
  public String consumerServiceIndex;
  public String consumingServiceIndex;

  public SignConfiguration() {
    keyIdentifierType = KeyIdentifierType.X509_CERT_DIRECT;
    // nameIdFormat = "email";
  }

  public SignConfiguration withKey(RSAPrivateKey key) {
    this.privatekey = key;
    return this;
  }

  public SignConfiguration withCertificate(X509Certificate certificate) {
    this.certificate = certificate;
    return this;
  }

  public SignConfiguration withServiceProviderName(String serviceProviderName) {
    this.serviceProviderName = serviceProviderName;
    return this;
  }

  public SignConfiguration withDestination(String destination) {
    this.destination = destination;
    return this;
  }

  public SignConfiguration withAcsUrl(String acsUrl) {
    this.acsUrl = acsUrl;
    return this;
  }

  public SignConfiguration withIssuer(String issuer) {
    this.issuer = issuer;
    return this;
  }

  public SignConfiguration withSubject(String subject) {
    this.subject = subject;
    return this;
  }

  public SignConfiguration withNameIdFormat(String nameIdFormat) {
    this.nameIdFormat = nameIdFormat;
    return this;
  }

  public SignConfiguration withRequestedAuthnContext(String requestedAuthnContext) {
    this.requestedAuthnContext = requestedAuthnContext;
    return this;
  }

  public SignConfiguration withIdpId(String idpId) {
    this.idpId = idpId;
    return this;
  }

  public SignConfiguration withIdpLocation(String idpLocation) {
    this.idpLocation = idpLocation;
    return this;
  }

  public SignConfiguration withRequesterId(String requesterId) {
    this.requesterId = requesterId;
    return this;
  }

  public SignConfiguration withSignatureMethod(String signingMethod) {
    this.signingMethod = signingMethod;
    return this;
  }

  public SignConfiguration withDigestMethod(String digestMethod) {
    this.digestMethod = digestMethod;
    return this;
  }

  public SignConfiguration withKeyIdentifierType(KeyIdentifierType keyIdentifierType) {
    this.keyIdentifierType = keyIdentifierType;
    return this;
  }

  public SignConfiguration withForceAuthn(boolean forceAuthn) {
    this.forceAuthn = forceAuthn;
    return this;
  }

  public SignConfiguration withBindingType(BindingType bindingType) {
    this.bindingType = bindingType;
    return this;
  }

  public SignConfiguration withRelayState(String relayState) {
    this.relayState = relayState;
    return this;
  }

  public SignConfiguration withUrlEncodeOutput(boolean urlEncodeOutput) {
    this.urlEncodeOutput = urlEncodeOutput;
    return this;
  }
  public SignConfiguration withConsumerServiceIndex(String index) {
    this.consumerServiceIndex = index;
    return this;
  }
  public SignConfiguration withConsumingServiceIndex(String index) {
    this.consumingServiceIndex = index;
    return this;
  }

}
