package com.google.apigee.edgecallouts.samlauthn;

import com.apigee.flow.execution.ExecutionResult;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class TestSamlAuthnCallout extends CalloutTestBase {

  private static Document docFromStream(InputStream inputStream)
      throws IOException, ParserConfigurationException, SAXException {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    Document doc = dbf.newDocumentBuilder().parse(inputStream);
    return doc;
  }

  @Test
  public void missingPrivateKey() throws Exception {
    String method = "missingPrivateKey() ";
    String expectedError = "private-key resolves to an empty string";

    Map<String, String> props = new HashMap<String, String>();

    Generate callout = new Generate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object exception = msgCtxt.getVariable("samlauthn_exception");
    Assert.assertNotNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("samlauthn_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    // System.out.printf("expected error: %s\n", errorOutput);
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("samlauthn_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");
  }

  @Test
  public void missingCertificate() throws Exception {
    String method = "missingCertificate() ";
    String expectedError = "certificate resolves to an empty string";
    msgCtxt.setVariable("my-private-key", pairs[0].privateKey);

    Map<String, String> props = new HashMap<String, String>();
    // props.put("debug", "true");
    props.put("private-key", "{my-private-key}");
    props.put("private-key-password", "Secret123");
    props.put("output-variable", "output");

    Generate callout = new Generate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object exception = msgCtxt.getVariable("samlauthn_exception");
    Assert.assertNotNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("samlauthn_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("samlauthn_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");
  }

  @Test
  public void missingDestination() throws Exception {
    String method = "missingDestination() ";
    String expectedError = "destination resolves to an empty string";
    String expectedException = "java.lang.IllegalStateException: " + expectedError;
    String destination = "https://idp.example.com/SSOService.php";
    String providerName = "TestServiceProvider";
    String issuer = "https://sp.example.com/demo1/metadata.php";
    String acsUrl = "https://sp.example.com/demo1/index.php?acs";

    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);
    msgCtxt.setVariable("destination", destination);
    msgCtxt.setVariable("providerName", providerName);
    msgCtxt.setVariable("issuer", issuer);
    msgCtxt.setVariable("acsUrl", acsUrl);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    //props.put("destination", "{destination}");
    props.put("service-provider-name", "{providerName}");
    props.put("issuer", "{issuer}");
    props.put("acs-url", "{acsUrl}");
    props.put("output-variable", "output");

    Generate callout = new Generate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object exception = msgCtxt.getVariable("samlauthn_exception");
    Assert.assertNotNull(exception, "exception not as expected");
    Assert.assertEquals(exception, expectedException, "exception not as expected");
    Object errorOutput = msgCtxt.getVariable("samlauthn_error");
    Assert.assertNotNull(errorOutput, "error not as expected");
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("samlauthn_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");
  }

  @Test
  public void missingProviderName() throws Exception {
    String method = "missingProviderName() ";
    String expectedError = "service-provider-name resolves to an empty string";
    String expectedException = "java.lang.IllegalStateException: " + expectedError;
    String destination = "https://idp.example.com/SSOService.php";
    String providerName = "TestServiceProvider";
    String issuer = "https://sp.example.com/demo1/metadata.php";
    String acsUrl = "https://sp.example.com/demo1/index.php?acs";

    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);
    msgCtxt.setVariable("destination", destination);
    msgCtxt.setVariable("providerName", providerName);
    msgCtxt.setVariable("issuer", issuer);
    msgCtxt.setVariable("acsUrl", acsUrl);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("destination", "{destination}");
    //props.put("service-provider-name", "{providerName}");
    props.put("issuer", "{issuer}");
    props.put("acs-url", "{acsUrl}");
    props.put("output-variable", "output");

    Generate callout = new Generate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object exception = msgCtxt.getVariable("samlauthn_exception");
    Assert.assertNotNull(exception, "exception not as expected");
    Assert.assertEquals(exception, expectedException, "exception not as expected");
    Object errorOutput = msgCtxt.getVariable("samlauthn_error");
    Assert.assertNotNull(errorOutput, "error not as expected");
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("samlauthn_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");
  }

  @Test
  public void missingIssuer() throws Exception {
    String method = "missingIssuer() ";
    String expectedError = "issuer resolves to an empty string";
    String expectedException = "java.lang.IllegalStateException: " + expectedError;
    String destination = "https://idp.example.com/SSOService.php";
    String providerName = "TestServiceProvider";
    String issuer = "https://sp.example.com/demo1/metadata.php";
    String acsUrl = "https://sp.example.com/demo1/index.php?acs";

    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);
    msgCtxt.setVariable("destination", destination);
    msgCtxt.setVariable("providerName", providerName);
    msgCtxt.setVariable("issuer", issuer);
    msgCtxt.setVariable("acsUrl", acsUrl);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("destination", "{destination}");
    props.put("service-provider-name", "{providerName}");
    //props.put("issuer", "{issuer}");
    props.put("acs-url", "{acsUrl}");
    props.put("output-variable", "output");

    Generate callout = new Generate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object exception = msgCtxt.getVariable("samlauthn_exception");
    Assert.assertNotNull(exception, "exception not as expected");
    Assert.assertEquals(exception, expectedException, "exception not as expected");
    Object errorOutput = msgCtxt.getVariable("samlauthn_error");
    Assert.assertNotNull(errorOutput, "error not as expected");
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("samlauthn_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");
  }

  @Test
  public void missingAcsUrl() throws Exception {
    String method = "missingAcsUrl() ";
    String expectedError = "acs-url resolves to an empty string";
    String expectedException = "java.lang.IllegalStateException: " + expectedError;
    String destination = "https://idp.example.com/SSOService.php";
    String providerName = "TestServiceProvider";
    String issuer = "https://sp.example.com/demo1/metadata.php";
    String acsUrl = "https://sp.example.com/demo1/index.php?acs";

    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);
    msgCtxt.setVariable("destination", destination);
    msgCtxt.setVariable("providerName", providerName);
    msgCtxt.setVariable("issuer", issuer);
    msgCtxt.setVariable("acsUrl", acsUrl);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("destination", "{destination}");
    props.put("service-provider-name", "{providerName}");
    props.put("issuer", "{issuer}");
    //props.put("acs-url", "{acsUrl}");
    props.put("output-variable", "output");

    Generate callout = new Generate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object exception = msgCtxt.getVariable("samlauthn_exception");
    Assert.assertNotNull(exception, "exception not as expected");
    Assert.assertEquals(exception, expectedException, "exception not as expected");
    Object errorOutput = msgCtxt.getVariable("samlauthn_error");
    Assert.assertNotNull(errorOutput, "error not as expected");
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("samlauthn_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");
  }

  @Test
  public void validResult() throws Exception {
    String method = "validResult() ";
    String destination = "https://idp.example.com/SSOService.php";
    String providerName = "TestServiceProvider";
    String issuer = "https://sp.example.com/demo1/metadata.php";
    String acsUrl = "https://sp.example.com/demo1/index.php?acs";

    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);
    msgCtxt.setVariable("destination", destination);
    msgCtxt.setVariable("providerName", providerName);
    msgCtxt.setVariable("issuer", issuer);
    msgCtxt.setVariable("acsUrl", acsUrl);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("destination", "{destination}");
    props.put("service-provider-name", "{providerName}");
    props.put("name-id-format", "email");
    props.put("issuer", "{issuer}");
    props.put("acs-url", "{acsUrl}");
    props.put("output-variable", "output");

    Generate callout = new Generate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("samlauthn_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("samlauthn_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("samlauthn_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));

    // signature
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, method + "Signature element");

    // SignatureMethod (default)
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureMethod");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureMethod element");
    Element element = (Element) nl.item(0);
    String signatureMethodAlgorithm = element.getAttribute("Algorithm");
    Assert.assertEquals(signatureMethodAlgorithm, "http://www.w3.org/2000/09/xmldsig#rsa-sha1");

    // c14n
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "CanonicalizationMethod");
    Assert.assertEquals(nl.getLength(), 1, method + "CanonicalizationMethod element");
    element = (Element) nl.item(0);
    String canonicalizationMethodAlgorithm = element.getAttribute("Algorithm");
    Assert.assertEquals(canonicalizationMethodAlgorithm, "http://www.w3.org/2001/10/xml-exc-c14n#");

    // Reference
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference");
    Assert.assertEquals(nl.getLength(), 1, method + "Reference element");

    // DigestMethod
    for (int i = 0; i < nl.getLength(); i++) {
      element = (Element) nl.item(i);
      NodeList digestMethodNodes =
          element.getElementsByTagNameNS(XMLSignature.XMLNS, "DigestMethod");
      Assert.assertEquals(digestMethodNodes.getLength(), 1, method + "DigestMethod element");
      element = (Element) digestMethodNodes.item(0);
      String digestAlg = element.getAttribute("Algorithm");
      Assert.assertEquals(digestAlg, "http://www.w3.org/2000/09/xmldsig#sha1");
    }

    // SignatureValue
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureValue");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureValue element");
  }

  @Test
  public void rsasha256Signature() throws Exception {
    String method = "rsasha256Signature() ";
    String destination = "https://idp.example.com/SSOService.php";
    String providerName = "TestServiceProvider";
    String issuer = "https://sp.example.com/demo1/metadata.php";
    String acsUrl = "https://sp.example.com/demo1/index.php?acs";

    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);
    msgCtxt.setVariable("destination", destination);
    msgCtxt.setVariable("providerName", providerName);
    msgCtxt.setVariable("issuer", issuer);
    msgCtxt.setVariable("acsUrl", acsUrl);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("destination", "{destination}");
    props.put("service-provider-name", "{providerName}");
    props.put("issuer", "{issuer}");
    props.put("acs-url", "{acsUrl}");
    props.put("signature-method", "rsa-sha256");
    props.put("output-variable", "output");

    Generate callout = new Generate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("samlauthn_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("samlauthn_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("samlauthn_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));

    // signature
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, method + "Signature element");

    // SignatureMethod (sha256)
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureMethod");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureMethod element");
    Element element = (Element) nl.item(0);
    String signatureMethodAlgorithm = element.getAttribute("Algorithm");
    Assert.assertEquals(
        signatureMethodAlgorithm, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
  }

  @Test
  public void digestSha256() throws Exception {
    String method = "digestSha256() ";
    String destination = "https://idp.example.com/SSOService.php";
    String providerName = "TestServiceProvider";
    String issuer = "https://sp.example.com/demo1/metadata.php";
    String acsUrl = "https://sp.example.com/demo1/index.php?acs";

    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);
    msgCtxt.setVariable("destination", destination);
    msgCtxt.setVariable("providerName", providerName);
    msgCtxt.setVariable("issuer", issuer);
    msgCtxt.setVariable("acsUrl", acsUrl);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("destination", "{destination}");
    props.put("service-provider-name", "{providerName}");
    props.put("issuer", "{issuer}");
    props.put("acs-url", "{acsUrl}");
    props.put("digest-method", "sha256");
    props.put("output-variable", "output");

    Generate callout = new Generate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("samlauthn_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("samlauthn_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("samlauthn_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));

    // signature
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, method + "Signature element");

    // Reference
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference");
    Assert.assertEquals(nl.getLength(), 1, method + "Reference element");

    // DigestMethod
    for (int i = 0; i < nl.getLength(); i++) {
      Element element = (Element) nl.item(i);
      NodeList digestMethodNodes =
          element.getElementsByTagNameNS(XMLSignature.XMLNS, "DigestMethod");
      Assert.assertEquals(digestMethodNodes.getLength(), 1, method + "DigestMethod element");
      element = (Element) digestMethodNodes.item(0);
      String digestAlg = element.getAttribute("Algorithm");
      Assert.assertEquals(digestAlg, "http://www.w3.org/2001/04/xmlenc#sha256");
    }
  }

  @Test
  public void mismatchedKeyAndCertificate() throws Exception {
    String method = "mismatchedKeyAndCertificate() ";
    String expectedError =
        "public key mismatch. The public key contained in the certificate does not match the private key.";

    String expectedException = "java.security.KeyException: " + expectedError;
    String destination = "https://idp.example.com/SSOService.php";
    String providerName = "TestServiceProvider";
    String issuer = "https://sp.example.com/demo1/metadata.php";
    String acsUrl = "https://sp.example.com/demo1/index.php?acs";

    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[1].certificate);
    msgCtxt.setVariable("destination", destination);
    msgCtxt.setVariable("providerName", providerName);
    msgCtxt.setVariable("issuer", issuer);
    msgCtxt.setVariable("acsUrl", acsUrl);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("destination", "{destination}");
    props.put("service-provider-name", "{providerName}");
    props.put("issuer", "{issuer}");
    props.put("acs-url", "{acsUrl}");
    props.put("digest-method", "sha256");
    props.put("output-variable", "output");

    Generate callout = new Generate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object exception = msgCtxt.getVariable("samlauthn_exception");
    Assert.assertEquals(exception, expectedException, method + "exception");
    Object errorOutput = msgCtxt.getVariable("samlauthn_error");
    Assert.assertEquals(errorOutput, expectedError, "errorOutput");
  }

    @Test
  public void withIdpLocation() throws Exception {
    String method = "withIdpLocation() ";
    String destination = "https://idp.example.com/SSOService.php";
    String idpId = "https://idp.example.com/idp/saml2/metadata";
    String idpLocation = "https://idp.example.com/idp/saml2/sso";
    String providerName = "TestServiceProvider";
    String issuer = "https://sp.example.com/demo1/metadata.php";
    String acsUrl = "https://sp.example.com/demo1/index.php?acs";

    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);
    msgCtxt.setVariable("destination", destination);
    msgCtxt.setVariable("providerName", providerName);
    msgCtxt.setVariable("issuer", issuer);
    msgCtxt.setVariable("acsUrl", acsUrl);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("destination", "{destination}");
    props.put("service-provider-name", "{providerName}");
    props.put("issuer", "{issuer}");
    props.put("acs-url", "{acsUrl}");
    props.put("idp-id", idpId);
    props.put("idp-location", idpLocation);
    props.put("output-variable", "output");

    Generate callout = new Generate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("samlauthn_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("samlauthn_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("samlauthn_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));

    // signature
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, method + "Signature element");

    // SignatureMethod (sha256)
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureMethod");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureMethod element");
    Element element = (Element) nl.item(0);
    String signatureMethodAlgorithm = element.getAttribute("Algorithm");
    Assert.assertNotNull(signatureMethodAlgorithm);
  }

}
