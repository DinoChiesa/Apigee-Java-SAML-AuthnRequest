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
import com.google.apigee.util.TimeResolver;
import com.google.apigee.util.XmlUtils;
import com.google.apigee.xml.Namespaces;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
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
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.naming.InvalidNameException;
import javax.security.auth.x500.X500Principal;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
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
import org.xml.sax.SAXException;

public class Generate extends SamlAuthnCalloutBase implements Execution {

  private final static String AUTHN_REQUEST_TEMPLATE =
""
+ "<samlp:AuthnRequest\n"
+ "    xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol'\n"
+ "    xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'\n"
+ "    Version='2.0'\n"
+ "    ProviderName='@@PROVIDER_NAME@@'\n"
+ "    IssueInstant='@@ISSUE_INSTANT@@'\n"
+ "    Destination='@@DESTINATION@@'\n"
+ "    ProtocolBinding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'\n"
+ "    AssertionConsumerServiceURL='@@ACS_URL@@'>\n"
+ "  <saml:Issuer>@@ISSUER@@</saml:Issuer>\n"
+ "  <samlp:NameIDPolicy Format='@@NAMEID_FORMAT@@' AllowCreate='true'/>\n"
+ "  <samlp:RequestedAuthnContext Comparison='exact'>\n"
+ "    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>\n"
+ "  </samlp:RequestedAuthnContext>\n"
    + "</samlp:AuthnRequest>\n";

  public Generate(Map properties) {
    super(properties);
  }

  // public static String toPrettyString(Document document, int indent) {
  //   try {
  //     // Remove whitespaces outside tags
  //     document.normalize();
  //     XPath xPath = XPathFactory.newInstance().newXPath();
  //     NodeList nodeList =
  //         (NodeList)
  //             xPath.evaluate("//text()[normalize-space()='']", document, XPathConstants.NODESET);
  //
  //     for (int i = 0; i < nodeList.getLength(); ++i) {
  //       Node node = nodeList.item(i);
  //       node.getParentNode().removeChild(node);
  //     }
  //
  //     // Setup pretty print options
  //     TransformerFactory transformerFactory = TransformerFactory.newInstance();
  //     transformerFactory.setAttribute("indent-number", indent);
  //     Transformer transformer = transformerFactory.newTransformer();
  //     transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
  //     transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
  //     transformer.setOutputProperty(OutputKeys.INDENT, "yes");
  //
  //     // Return pretty print xml string
  //     StringWriter stringWriter = new StringWriter();
  //     transformer.transform(new DOMSource(document), new StreamResult(stringWriter));
  //     return stringWriter.toString();
  //   } catch (Exception e) {
  //     throw new RuntimeException(e);
  //   }
  // }

  // public static Element getFirstChildElement(Element element) {
  //   for (Node currentChild = element.getFirstChild();
  //        currentChild != null;
  //        currentChild = currentChild.getNextSibling()) {
  //     if (currentChild instanceof Element) {
  //       return (Element) currentChild;
  //     }
  //   }
  //   return null;
  // }

  private static String getISOTimestamp(int offsetFromNow) {
    // ex: '2019-11-03T10:15:30Z'
    ZonedDateTime zdt = ZonedDateTime.now(ZoneOffset.UTC).truncatedTo(ChronoUnit.SECONDS);
    if (offsetFromNow != 0) zdt = zdt.plusSeconds(offsetFromNow);
    return zdt.format(DateTimeFormatter.ISO_INSTANT);
    // return ZonedDateTime.ofInstant(Instant.ofEpochSecond(secondsSinceEpoch), ZoneOffset.UTC)
    //     .format(DateTimeFormatter.ISO_INSTANT);
  }

  private String sign_RSA(SignConfiguration signConfiguration, MessageContext msgCtxt)
      throws InstantiationException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
          KeyException, MarshalException, XMLSignatureException, TransformerException,
             CertificateEncodingException, InvalidNameException, IOException,
             SAXException, ParserConfigurationException {

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

    XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");

    String nameIdFormat = (signConfiguration.nameIdFormat != null && signConfiguration.nameIdFormat.equals("transient"))  ?
      "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" :  "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

    String samlAuthnRequest = AUTHN_REQUEST_TEMPLATE
      .replaceFirst("@@PROVIDER_NAME@@", signConfiguration.providerName)
      .replaceFirst("@@ISSUE_INSTANT@@", getISOTimestamp(0))
      .replaceFirst("@@DESTINATION@@", signConfiguration.destination)
      .replaceFirst("@@ACS_URL@@", signConfiguration.acsUrl)
      .replaceFirst("@@ISSUER@@", signConfiguration.issuer)
      .replaceFirst("@@NAMEID_FORMAT@@", nameIdFormat);

    Document doc = XmlUtils.parseXml(samlAuthnRequest);
    Element authnRequest = doc.getDocumentElement();

    // 1. Set the ID of the AuthnRequest element
    String bodyId = java.util.UUID.randomUUID().toString();
    authnRequest.setAttribute("ID", bodyId);
    authnRequest.setIdAttribute("ID", true);
    msgCtxt.setVariable(varName("request_id"), bodyId);

    // 2. set up the ds:Reference
    String digestMethodUri =
        ((signConfiguration.digestMethod != null)
                && (signConfiguration.digestMethod.toLowerCase().equals("sha256")))
            ? DigestMethod.SHA256
            : DigestMethod.SHA1;

    DigestMethod digestMethod = signatureFactory.newDigestMethod(digestMethodUri, null);

    List<Transform> transforms = Arrays.asList(
        signatureFactory.newTransform("http://www.w3.org/2001/10/xml-exc-c14n#", (TransformParameterSpec) null),

        signatureFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));

    List<Reference> references = new ArrayList<Reference>();
    references.add(
          signatureFactory.newReference(
              "#" + bodyId, digestMethod, transforms, null, null));

    // 4. add <SignatureMethod Algorithm="..."?>
    String signingMethodUri =
        ((signConfiguration.signingMethod != null)
                && (signConfiguration.signingMethod.toLowerCase().equals("rsa-sha256")))
            ? "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
            : "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

    SignatureMethod signatureMethod = signatureFactory.newSignatureMethod(signingMethodUri, null);

    // 5. c14n method
    CanonicalizationMethod canonicalizationMethod =
        signatureFactory.newCanonicalizationMethod(
            CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null);

    // 6. get the SignedInfo
    DOMSignContext signingContext = new DOMSignContext(signConfiguration.privatekey, authnRequest);
    SignedInfo signedInfo =
        signatureFactory.newSignedInfo(canonicalizationMethod, signatureMethod, references);
    KeyInfoFactory kif = signatureFactory.getKeyInfoFactory();

    // 7. set up the KeyInfo
    // The marshalled XMLSignature will be added as the last child element
    // of the specified parent node.
    KeyInfo keyInfo = null;
    if (signConfiguration.keyIdentifierType == KeyIdentifierType.X509_CERT_DIRECT) {
      // <KeyInfo>
      //   <X509Data>
      //     <X509Certificate>MIICAjCCAWugAwIBAgIQwZyW5YOCXZxHg1MBV2CpvDANBgkhkiG9w0BAQnEdD9tI7IYAAoK4O+35EOzcXbvc4Kzz7BQnulQ=</X509Certificate>
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

    XMLSignature signature = signatureFactory.newXMLSignature(signedInfo, keyInfo);
    signature.sign(signingContext);

    // emit the resulting document
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    Transformer transformer = TransformerFactory.newInstance().newTransformer();
    transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
    transformer.transform(new DOMSource(doc), new StreamResult(baos));
    return new String(baos.toByteArray(), StandardCharsets.UTF_8);
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

  private String getSigningMethod(MessageContext msgCtxt) throws Exception {
    String signingMethod = getSimpleOptionalProperty("signing-method", msgCtxt);
    if (signingMethod == null) return null;
    signingMethod = signingMethod.trim();
    // warn on invalid values
    if (!signingMethod.toLowerCase().equals("rsa-sha1")
        && !signingMethod.toLowerCase().equals("rsa-sha256")) {
      msgCtxt.setVariable(varName("WARNING"), "invalid value for signing-method");
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

  protected String getProviderName(MessageContext msgCtxt) throws Exception {
    return getSimpleRequiredProperty("provider-name", msgCtxt);
  }

  protected String getDestination(MessageContext msgCtxt) throws Exception {
    return getSimpleRequiredProperty("destination", msgCtxt);
  }

  protected String getAcsUrl(MessageContext msgCtxt) throws Exception {
    return getSimpleRequiredProperty("acs-url", msgCtxt);
  }

  protected String getIssuer(MessageContext msgCtxt) throws Exception {
    return getSimpleRequiredProperty("issuer", msgCtxt);
  }

  protected String getNameIdFormat(MessageContext msgCtxt) throws Exception {
    return getSimpleOptionalProperty("name-id-format", msgCtxt);
  }

  enum KeyIdentifierType {
    NOT_SPECIFIED,
    //THUMBPRINT,
    X509_CERT_DIRECT,
    //BST_DIRECT_REFERENCE,
    RSA_KEY_VALUE;
    //ISSUER_SERIAL;

    static KeyIdentifierType fromString(String s) {
       for (KeyIdentifierType t : KeyIdentifierType.values()) {
         if (t.name().equals(s)) return t;
       }
       return KeyIdentifierType.NOT_SPECIFIED;
    }
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

  static class SignConfiguration {
    // required
    public RSAPrivateKey privatekey;
    public X509Certificate certificate;
    public String destination;
    public String providerName;
    public String acsUrl;
    public String issuer;
    // optional
    public String nameIdFormat;
    public String signingMethod;
    public String digestMethod;
    public KeyIdentifierType keyIdentifierType;

    public SignConfiguration() {
      keyIdentifierType = KeyIdentifierType.X509_CERT_DIRECT;
      nameIdFormat = "email";
    }

    public SignConfiguration withKey(RSAPrivateKey key) {
      this.privatekey = key;
      return this;
    }

    public SignConfiguration withCertificate(X509Certificate certificate) {
      this.certificate = certificate;
      return this;
    }

    public SignConfiguration withProviderName(String providerName) {
      this.providerName = providerName;
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

    public SignConfiguration withNameIdFormat(String nameIdFormat) {
      this.nameIdFormat = nameIdFormat;
      return this;
    }

    public SignConfiguration withSigningMethod(String signingMethod) {
      this.signingMethod = signingMethod;
      return this;
    }

    public SignConfiguration withDigestMethod(String digestMethod) {
      this.digestMethod = digestMethod;
      return this;
    }

    public SignConfiguration withKeyIdentifierType(KeyIdentifierType kit) {
      this.keyIdentifierType = kit;
      return this;
    }

  }

  public ExecutionResult execute(final MessageContext msgCtxt, final ExecutionContext execContext) {
    try {
      SignConfiguration signConfiguration =
          new SignConfiguration()
              .withKey(getPrivateKey(msgCtxt))
              .withCertificate(getCertificate(msgCtxt))
              .withProviderName(getProviderName(msgCtxt))
              .withDestination(getDestination(msgCtxt))
              .withAcsUrl(getAcsUrl(msgCtxt))
              .withIssuer(getIssuer(msgCtxt))
              .withNameIdFormat(getNameIdFormat(msgCtxt))
              .withSigningMethod(getSigningMethod(msgCtxt))
              .withDigestMethod(getDigestMethod(msgCtxt))
              .withKeyIdentifierType(getKeyIdentifierType(msgCtxt));

      String authnRequestXmlString = sign_RSA(signConfiguration, msgCtxt);
      msgCtxt.setVariable(getOutputVar(msgCtxt), authnRequestXmlString);
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
