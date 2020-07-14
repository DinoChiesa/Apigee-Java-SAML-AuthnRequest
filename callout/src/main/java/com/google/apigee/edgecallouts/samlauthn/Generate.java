// Copyright 2018-2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package com.google.apigee.edgecallouts.samlauthn;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.google.apigee.util.XmlUtils;
import com.google.apigee.xml.Namespaces;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class Generate extends SamlAuthnCalloutBase implements Execution {

  public Generate(Map properties) {
    super(properties);
  }

  private static String getISOTimestamp(int offsetFromNow) {
    // ex: '2019-11-03T10:15:30Z'
    ZonedDateTime zdt = ZonedDateTime.now(ZoneOffset.UTC).truncatedTo(ChronoUnit.SECONDS);
    if (offsetFromNow != 0) zdt = zdt.plusSeconds(offsetFromNow);
    return zdt.format(DateTimeFormatter.ISO_INSTANT);
  }

  private static Element insertAfter(Element newElement, Element existingElement) {
    existingElement.getParentNode().insertBefore(newElement, existingElement.getNextSibling());
    return newElement;
  }

  private static String getFormatString(String nameIdFormatOption) {
    if (nameIdFormatOption == null) {
      throw new IllegalStateException("that value for name-id-format is not supported");
    }
    if (nameIdFormatOption.equals("transient")) {
      return Constants.NAME_ID_TRANSIENT;
    }
    if (nameIdFormatOption.equals("persistent")) {
      return Constants.NAME_ID_PERSISTENT;
    }
    if (nameIdFormatOption.equals("email")) {
      return Constants.NAME_ID_EMAIL;
    }
    if (nameIdFormatOption.equals("unspecified")) {
      return Constants.NAME_ID_UNSPECIFIED;
    }
    throw new IllegalStateException("that value for name-id-format is not supported");
  }

  public static String compressAndEncode(String data) throws IOException {
    try (ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
      try (DeflaterOutputStream stream =
          new DeflaterOutputStream(buffer, new Deflater(Deflater.DEFLATED, true))) {
        stream.write(data.getBytes(StandardCharsets.UTF_8));
      }
      byte[] compressed = buffer.toByteArray();
      String base64 = Base64.getEncoder().encodeToString(compressed);
      return base64;
    }
  }

  private void sign_RSA(SignConfiguration signConfiguration, MessageContext msgCtxt)
      throws Exception {
    // 0. validate that the cert signs the public key that corresponds to the private key
    RSAPublicKey certPublicKey = (RSAPublicKey) signConfiguration.certificate.getPublicKey();
    final byte[] certModulus = certPublicKey.getModulus().toByteArray();
    RSAPrivateKey configPrivateKey = (RSAPrivateKey) signConfiguration.privatekey;
    final byte[] keyModulus = configPrivateKey.getModulus().toByteArray();
    String encodedCertModulus = Base64.getEncoder().encodeToString(certModulus);
    String encodedKeyModulus = Base64.getEncoder().encodeToString(keyModulus);
    if (!encodedCertModulus.equals(encodedKeyModulus)) {
      throw new KeyException(
          "public key mismatch. The public key contained in the certificate does not match the private key.");
    }

    // 1. start with the core AuthnRequest
    String samlAuthnRequest =
        Constants.AUTHN_REQUEST_TEMPLATE
            .replaceFirst("@@SERVICE_PROVIDER_NAME@@", signConfiguration.serviceProviderName)
            .replaceFirst("@@ISSUE_INSTANT@@", getISOTimestamp(0))
            .replaceFirst("@@DESTINATION@@", signConfiguration.destination)
            .replaceFirst("@@ACS_URL@@", signConfiguration.acsUrl)
            .replaceFirst("@@ISSUER@@", signConfiguration.issuer);

    Document doc = XmlUtils.parseXml(samlAuthnRequest);
    Element authnRequest = doc.getDocumentElement();
    NodeList nodes = doc.getElementsByTagNameNS(Namespaces.SAML, "Issuer");
    Element issuer = (Element) nodes.item(0);
    Element current = issuer;

    // 2. conditionally add ForceAuthn, ConsumerServiceIndex, ConsumingServiceIndex
    if (signConfiguration.forceAuthn) {
      authnRequest.setAttribute("ForceAuthn", "true");
    }
    if (signConfiguration.consumerServiceIndex != null) {
      authnRequest.setAttribute(
          "AssertionConsumerServiceIndex", signConfiguration.consumerServiceIndex);
    }
    if (signConfiguration.consumingServiceIndex != null) {
      authnRequest.setAttribute(
          "AssertionConsumingServiceIndex", signConfiguration.consumingServiceIndex);
    }

    // 3. Optional elements
    //
    // The Ordering of the following is important.
    // <sequence>
    //   <element ref="saml:Subject" minOccurs="0"/>
    //   <element ref="samlp:NameIDPolicy" minOccurs="0"/>
    //   <element ref="saml:Conditions" minOccurs="0"/>
    //   <element ref="samlp:RequestedAuthnContext" minOccurs="0"/>
    //   <element ref="samlp:Scoping" minOccurs="0"/>
    // </sequence>

    // 3a. conditionally include Subject. This is dosallowed by SAML2.0
    if (signConfiguration.subject != null) {
      Element subject = doc.createElementNS(Namespaces.SAML, "saml:Subject");
      subject.setTextContent(signConfiguration.subject);
      current = insertAfter(subject, current);
    }

    // 3b. conditionally include NameIDPolicy
    if (signConfiguration.nameIdFormat != null) {
      Element nameIdFormat = doc.createElementNS(Namespaces.SAMLP, "samlp:NameIDPolicy");
      String format = getFormatString(signConfiguration.nameIdFormat);
      nameIdFormat.setAttribute("Format", format);
      nameIdFormat.setAttribute("AllowCreate", "true");
      current = insertAfter(nameIdFormat, current);
    }

    // 3c. conditionally include RequestedAuthnContext/AuthnContextClassRef
    if (signConfiguration.requestedAuthnContext != null) {
      if (!signConfiguration.requestedAuthnContext.equals("password")) {
        throw new IllegalStateException("that value for RequestedAuthnContext not supported");
      }
      Element requestedAuthnContext =
          doc.createElementNS(Namespaces.SAMLP, "samlp:RequestedAuthnContext");
      requestedAuthnContext.setAttribute("Comparison", "exact");
      Element contextClassRef = doc.createElementNS(Namespaces.SAML, "saml:AuthnContextClassRef");
      contextClassRef.setTextContent(Constants.AUTHN_CONTEXT_CLASS_REF_PASSWORD);
      requestedAuthnContext.appendChild(contextClassRef);
      current = insertAfter(requestedAuthnContext, current);
    }

    // 3d. conditionally include Scoping
    if (signConfiguration.requesterId != null) {
      Element scoping = doc.createElementNS(Namespaces.SAMLP, "samlp:Scoping");
      Element requesterId = doc.createElementNS(Namespaces.SAMLP, "samlp:RequesterID");
      requesterId.setTextContent(signConfiguration.requesterId);
      scoping.appendChild(requesterId);
      current = insertAfter(scoping, current);
    } else if (signConfiguration.idpId != null) {
      Element scoping = doc.createElementNS(Namespaces.SAMLP, "samlp:Scoping");
      Element idpList = doc.createElementNS(Namespaces.SAMLP, "samlp:IDPList");
      Element idpEntry = doc.createElementNS(Namespaces.SAMLP, "samlp:IDPEntry");
      if (signConfiguration.idpLocation != null) {
        idpEntry.setAttribute("Loc", signConfiguration.idpLocation);
      }
      idpEntry.setAttribute("ProviderID", signConfiguration.idpId);
      idpList.appendChild(idpEntry);
      scoping.appendChild(idpList);
      current = insertAfter(scoping, current);
    }

    // 4. Set the ID of the AuthnRequest element
    String bodyId = "req-" + java.util.UUID.randomUUID().toString();
    authnRequest.setAttribute("ID", bodyId);
    authnRequest.setIdAttribute("ID", true);
    msgCtxt.setVariable(varName("request_id"), bodyId);

    // 5. get signing method URI
    String signatureMethodUri =
        ((signConfiguration.signingMethod != null)
                && (signConfiguration.signingMethod.toLowerCase().equals("rsa-sha256")))
            ? "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
            : "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

    // 6. export the XML itself
    msgCtxt.setVariable(varName("UnsignedRequest"), getXmlString(doc));

    if (signConfiguration.bindingType == BindingType.HTTP_REDIRECT) {
      String compressedAndBase64EncodedRequest = compressAndEncode(getXmlString(doc));

      // Structure of the signature base:
      //   SAMLRequest=value&RelayState=value&SigAlg=value
      //
      // Each value must be URL-encoded. Ordering is important.
      String encodedRequest = URLEncoder.encode(compressedAndBase64EncodedRequest, "UTF-8");
      String encodedRelayState = null;
      String encodedSigAlg = URLEncoder.encode(signatureMethodUri, "UTF-8");
      String signatureBase = "SAMLRequest=" + encodedRequest;
      if (signConfiguration.relayState != null) {
        encodedRelayState = URLEncoder.encode(signConfiguration.relayState, "UTF-8");
        signatureBase += "&RelayState=" + encodedRelayState;
      }
      signatureBase += "&SigAlg=" + encodedSigAlg;

      // The SAML Spec says that "SHA1WithRSA" or "SHA1withDSA" MUST be supported.
      // It does not say if other signature methods should or may be supported.
      // This implementation does not support DSA signatures.
      String signatureAlgorithm =
          ((signConfiguration.signingMethod != null)
                  && (signConfiguration.signingMethod.toLowerCase().equals("rsa-sha256")))
              ? "SHA256WithRSA"
              : "SHA1WithRSA";

      Signature signature = Signature.getInstance(signatureAlgorithm);
      signature.initSign(configPrivateKey);
      signature.update(signatureBase.getBytes(StandardCharsets.UTF_8));

      byte[] signatureResult = signature.sign();
      String base64EncodedSignature = Base64.getEncoder().encodeToString(signatureResult);

      // Set the four outut variables:
      // SAMLRequest
      // Signature
      // SigAlg
      // RelayState
      if (signConfiguration.urlEncodeOutput) {
        msgCtxt.setVariable(varName("SAMLRequest"), encodedRequest);
        msgCtxt.setVariable(
            varName("Signature"), URLEncoder.encode(base64EncodedSignature, "UTF-8"));
        msgCtxt.setVariable(varName("SigAlg"), URLEncoder.encode(signatureMethodUri, "UTF-8"));
        if (signConfiguration.relayState != null)
          msgCtxt.setVariable(varName("RelayState"), encodedRelayState);
      } else {
        msgCtxt.setVariable(varName("SAMLRequest"), compressedAndBase64EncodedRequest);
        msgCtxt.setVariable(varName("Signature"), base64EncodedSignature);
        msgCtxt.setVariable(varName("SigAlg"), signatureMethodUri);
        if (signConfiguration.relayState != null)
          msgCtxt.setVariable(varName("RelayState"), signConfiguration.relayState);
      }

    } else {
      // 5. set up the ds:Reference
      String digestMethodUri =
          ((signConfiguration.digestMethod != null)
                  && (signConfiguration.digestMethod.toLowerCase().equals("sha256")))
              ? DigestMethod.SHA256
              : DigestMethod.SHA1;

      XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
      DigestMethod digestMethod = signatureFactory.newDigestMethod(digestMethodUri, null);

      List<Transform> transforms =
          Arrays.asList(
              signatureFactory.newTransform(
                  "http://www.w3.org/2001/10/xml-exc-c14n#", (TransformParameterSpec) null),
              signatureFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));

      List<Reference> references = new ArrayList<Reference>();
      references.add(
          signatureFactory.newReference("#" + bodyId, digestMethod, transforms, null, null));

      // 6. add <SignatureMethod Algorithm="..."?>
      SignatureMethod signatureMethod =
          signatureFactory.newSignatureMethod(signatureMethodUri, null);

      // 7. c14n method
      CanonicalizationMethod canonicalizationMethod =
          signatureFactory.newCanonicalizationMethod(
              CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null);

      // 8. get the SignedInfo
      DOMSignContext signingContext =
          new DOMSignContext(signConfiguration.privatekey, authnRequest, issuer.getNextSibling());
      SignedInfo signedInfo =
          signatureFactory.newSignedInfo(canonicalizationMethod, signatureMethod, references);
      KeyInfoFactory kif = signatureFactory.getKeyInfoFactory();

      // 9. set up the KeyInfo
      // The marshalled XMLSignature will be added as the last child element
      // of the specified parent node.
      KeyInfo keyInfo = null;
      if (signConfiguration.keyIdentifierType == KeyIdentifierType.X509_CERT_DIRECT) {
        // <KeyInfo>
        //   <X509Data>
        //
        // <X509Certificate>MIICAjCCAWugAwIBAgIQwZyW5YOCXZxHg1MBV2CpvDANBgkhkiG9w0BAQnEdD9tI7IYAAoK4O+35EOzcXbvc4Kzz7BQnulQ=</X509Certificate>
        //   </X509Data>
        // </KeyInfo>
        Element x509Data = doc.createElementNS(Namespaces.XMLDSIG, "X509Data");
        Element x509Certificate = doc.createElementNS(Namespaces.XMLDSIG, "X509Certificate");
        x509Certificate.setTextContent(
            Base64.getEncoder().encodeToString(signConfiguration.certificate.getEncoded()));
        x509Data.appendChild(x509Certificate);
        javax.xml.crypto.XMLStructure structure = new javax.xml.crypto.dom.DOMStructure(x509Data);
        keyInfo = kif.newKeyInfo(java.util.Collections.singletonList(structure));
      } else if (signConfiguration.keyIdentifierType == KeyIdentifierType.RSA_KEY_VALUE) {
        // <KeyInfo>
        //   <KeyValue>
        //     <RSAKeyValue>
        //       <Modulus>B6PenDyT58LjZlG6LYD27IFCh1yO+4...yCP9YNDtsLZftMLoQ==</Modulus>
        //       <Exponent>AQAB</Exponent>
        //     </RSAKeyValue>
        //   </KeyValue>
        // </KeyInfo>
        Element keyValue = doc.createElementNS(Namespaces.XMLDSIG, "KeyValue");
        Element rsaKeyValue = doc.createElementNS(Namespaces.XMLDSIG, "RSAKeyValue");
        Element modulus = doc.createElementNS(Namespaces.XMLDSIG, "Modulus");
        Element exponent = doc.createElementNS(Namespaces.XMLDSIG, "Exponent");
        modulus.setTextContent(encodedCertModulus);
        final byte[] certExponent = certPublicKey.getPublicExponent().toByteArray();
        String encodedCertExponent = Base64.getEncoder().encodeToString(certExponent);
        exponent.setTextContent(encodedCertExponent);
        rsaKeyValue.appendChild(modulus);
        rsaKeyValue.appendChild(exponent);
        keyValue.appendChild(rsaKeyValue);
        javax.xml.crypto.XMLStructure structure = new javax.xml.crypto.dom.DOMStructure(keyValue);
        keyInfo = kif.newKeyInfo(java.util.Collections.singletonList(structure));
      }

      // 10. sign
      XMLSignature signature = signatureFactory.newXMLSignature(signedInfo, keyInfo);
      signature.sign(signingContext);

      // 12. set the string representation of the document into the output variable
      msgCtxt.setVariable(getOutputVar(msgCtxt), getXmlString(doc));
    }
  }

  protected String getXmlString(Document doc)
      throws TransformerConfigurationException, TransformerException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    Transformer transformer = TransformerFactory.newInstance().newTransformer();
    transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
    transformer.transform(new DOMSource(doc), new StreamResult(baos));
    String xmlString = new String(baos.toByteArray(), StandardCharsets.UTF_8);
    return xmlString;
  }

  private static RSAPrivateKey readKey(String privateKeyPemString, String password)
      throws IOException, OperatorCreationException, PKCSException, InvalidKeySpecException,
          NoSuchAlgorithmException {
    if (privateKeyPemString == null) {
      throw new IllegalStateException("PEM String is null");
    }
    if (password == null) password = "";

    PEMParser pr = null;
    try {
      pr = new PEMParser(new StringReader(privateKeyPemString));
      Object o = pr.readObject();

      if (o == null) {
        throw new IllegalStateException("Parsed object is null.  Bad input.");
      }
      if (!((o instanceof PEMEncryptedKeyPair)
          || (o instanceof PKCS8EncryptedPrivateKeyInfo)
          || (o instanceof PrivateKeyInfo)
          || (o instanceof PEMKeyPair))) {
        // System.out.printf("found %s\n", o.getClass().getName());
        throw new IllegalStateException(
            "Didn't find OpenSSL key. Found: " + o.getClass().getName());
      }

      JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

      if (o instanceof PEMKeyPair) {
        // eg, "openssl genrsa -out keypair-rsa-2048-unencrypted.pem 2048"
        return (RSAPrivateKey) converter.getPrivateKey(((PEMKeyPair) o).getPrivateKeyInfo());
      }

      if (o instanceof PrivateKeyInfo) {
        // eg, "openssl genpkey  -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out keypair.pem"
        return (RSAPrivateKey) converter.getPrivateKey((PrivateKeyInfo) o);
      }

      if (o instanceof PKCS8EncryptedPrivateKeyInfo) {
        // eg, "openssl genpkey -algorithm rsa -aes-128-cbc -pkeyopt rsa_keygen_bits:2048 -out
        // private-encrypted.pem"
        PKCS8EncryptedPrivateKeyInfo pkcs8EncryptedPrivateKeyInfo =
            (PKCS8EncryptedPrivateKeyInfo) o;
        JceOpenSSLPKCS8DecryptorProviderBuilder decryptorProviderBuilder =
            new JceOpenSSLPKCS8DecryptorProviderBuilder();
        InputDecryptorProvider decryptorProvider =
            decryptorProviderBuilder.build(password.toCharArray());
        PrivateKeyInfo privateKeyInfo =
            pkcs8EncryptedPrivateKeyInfo.decryptPrivateKeyInfo(decryptorProvider);
        return (RSAPrivateKey) converter.getPrivateKey(privateKeyInfo);
      }

      if (o instanceof PEMEncryptedKeyPair) {
        // eg, "openssl genrsa -aes256 -out private-encrypted-aes-256-cbc.pem 2048"
        PEMDecryptorProvider decProv =
            new JcePEMDecryptorProviderBuilder().setProvider("BC").build(password.toCharArray());
        KeyPair keyPair = converter.getKeyPair(((PEMEncryptedKeyPair) o).decryptKeyPair(decProv));
        return (RSAPrivateKey) keyPair.getPrivate();
      }
    } finally {
      if (pr != null) {
        pr.close();
      }
    }
    throw new IllegalStateException("unknown PEM object");
  }

  private RSAPrivateKey getPrivateKey(MessageContext msgCtxt) throws Exception {
    String privateKeyPemString = getSimpleRequiredProperty("private-key", msgCtxt);
    privateKeyPemString = privateKeyPemString.trim();

    // clear any leading whitespace on each line
    privateKeyPemString = reformIndents(privateKeyPemString);
    String privateKeyPassword = getSimpleOptionalProperty("private-key-password", msgCtxt);
    if (privateKeyPassword == null) privateKeyPassword = "";
    return readKey(privateKeyPemString, privateKeyPassword);
  }

  private String getSignatureMethod(MessageContext msgCtxt) throws Exception {
    String signingMethod = getSimpleOptionalProperty("signature-method", msgCtxt);
    if (signingMethod == null) return null;
    signingMethod = signingMethod.trim();
    // warn on invalid values
    if (!signingMethod.toLowerCase().equals("rsa-sha1")
        && !signingMethod.toLowerCase().equals("rsa-sha256")) {
      msgCtxt.setVariable(varName("WARNING"), "invalid value for signature-method");
    }
    return signingMethod;
  }

  private String getDigestMethod(MessageContext msgCtxt) throws Exception {
    String digestMethod = getSimpleOptionalProperty("digest-method", msgCtxt);
    if (digestMethod == null) return null;
    digestMethod = digestMethod.trim();
    // warn on invalid values
    if (!digestMethod.toLowerCase().equals("sha1")
        && !digestMethod.toLowerCase().equals("sha256")) {
      msgCtxt.setVariable(varName("WARNING"), "invalid value for digest-method");
    }
    return digestMethod;
  }

  protected boolean getForceAuthn(MessageContext msgCtxt) {
    String value = (String) getSimpleOptionalProperty("force-authn", msgCtxt);
    if (value == null) return false;
    if (value.trim().toLowerCase().equals("true")) return true;
    return false;
  }

  protected boolean getUrlEncodeOutput(MessageContext msgCtxt) {
    String value = (String) getSimpleOptionalProperty("url-encode-output", msgCtxt);
    if (value == null) return false;
    if (value.trim().toLowerCase().equals("true")) return true;
    return false;
  }

  protected BindingType getBindingType(MessageContext msgCtxt) {
    String value = (String) getSimpleRequiredProperty("binding-type", msgCtxt);
    value = value.trim().toUpperCase();
    if (!value.startsWith("HTTP-")) {
      if (value.startsWith("HTTP")) {
        value = value.replaceAll("^HTTP", "HTTP-");
      } else {
        value = "HTTP-" + value;
      }
    }
    BindingType t = BindingType.fromString(value.replaceAll("-", "_"));
    if (t == BindingType.NOT_SPECIFIED) {
      msgCtxt.setVariable(varName("warning"), "unrecognized binding-type");
      return BindingType.HTTP_POST;
    }
    return t;
  }

  private KeyIdentifierType getKeyIdentifierType(MessageContext msgCtxt) throws Exception {
    String kitString = getSimpleOptionalProperty("key-identifier-type", msgCtxt);
    if (kitString == null) return KeyIdentifierType.X509_CERT_DIRECT;
    kitString = kitString.trim().toUpperCase();
    KeyIdentifierType t = KeyIdentifierType.fromString(kitString);
    if (t == KeyIdentifierType.NOT_SPECIFIED) {
      msgCtxt.setVariable(varName("warning"), "unrecognized key-identifier-type");
      return KeyIdentifierType.X509_CERT_DIRECT;
    }
    return t;
  }

  public ExecutionResult execute(final MessageContext msgCtxt, final ExecutionContext execContext) {
    try {
      SignConfiguration signConfiguration =
          new SignConfiguration()
              .withBindingType(getBindingType(msgCtxt))
              .withKey(getPrivateKey(msgCtxt))
              .withCertificate(getCertificate(msgCtxt))
              .withServiceProviderName(getSimpleRequiredProperty("service-provider-name", msgCtxt))
              .withDestination(getSimpleRequiredProperty("destination", msgCtxt))
              .withAcsUrl(getSimpleRequiredProperty("acs-url", msgCtxt))
              .withForceAuthn(getForceAuthn(msgCtxt))
              .withUrlEncodeOutput(getUrlEncodeOutput(msgCtxt))
              .withIssuer(getSimpleRequiredProperty("issuer", msgCtxt))
              // .withSubject(getSubject(msgCtxt))
              .withNameIdFormat(getSimpleOptionalProperty("name-id-format", msgCtxt))
              .withRequestedAuthnContext(
                  getSimpleOptionalProperty("requested-authn-context", msgCtxt))
              .withRequesterId(getSimpleOptionalProperty("requester-id", msgCtxt))
              .withIdpId(getSimpleOptionalProperty("idp-id", msgCtxt))
              .withIdpLocation(getSimpleOptionalProperty("idp-location", msgCtxt))
              .withSignatureMethod(getSignatureMethod(msgCtxt))
              .withDigestMethod(getDigestMethod(msgCtxt))
              .withKeyIdentifierType(getKeyIdentifierType(msgCtxt))
              .withRelayState(getSimpleOptionalProperty("relay-state", msgCtxt))
              .withConsumerServiceIndex(
                  getSimpleOptionalProperty("consumer-service-index", msgCtxt))
              .withConsumingServiceIndex(
                  getSimpleOptionalProperty("consuming-service-index", msgCtxt));

      sign_RSA(signConfiguration, msgCtxt);
      return ExecutionResult.SUCCESS;
    } catch (IllegalStateException exc1) {
      setExceptionVariables(exc1, msgCtxt);
      return ExecutionResult.ABORT;
    } catch (Exception e) {
      if (getDebug()) {
        String stacktrace = getStackTraceAsString(e);
        msgCtxt.setVariable(varName("stacktrace"), stacktrace);
      }
      setExceptionVariables(e, msgCtxt);
      return ExecutionResult.ABORT;
    }
  }
}
