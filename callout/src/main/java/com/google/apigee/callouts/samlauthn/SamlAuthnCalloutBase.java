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

package com.google.apigee.callouts.samlauthn;

import com.apigee.flow.message.MessageContext;
import java.io.ByteArrayInputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;

public abstract class SamlAuthnCalloutBase {
  private static final String _varprefix = "samlauthn_";
  private Map properties; // read-only
  private static final String variableReferencePatternString = "(.*?)\\{([^\\{\\} ]+?)\\}(.*?)";
  private static final Pattern variableReferencePattern =
      Pattern.compile(variableReferencePatternString);

  private static final String commonError = "^(.+?)[:;] (.+)$";
  private static final Pattern commonErrorPattern = Pattern.compile(commonError);

  public SamlAuthnCalloutBase(Map properties) {
    this.properties = properties;
  }

  static String varName(String s) {
    return _varprefix + s;
  }

  protected boolean getDebug() {
    String value = (String) this.properties.get("debug");
    if (value == null) return false;
    if (value.trim().toLowerCase().equals("true")) return true;
    return false;
  }

  protected String getOutputVar(MessageContext msgCtxt) throws Exception {
    String dest = getSimpleOptionalProperty("output-variable", msgCtxt);
    if (dest == null) {
      return "message.content";
    }
    return dest;
  }

  protected String getSimpleOptionalProperty(String propName, MessageContext msgCtxt) {
    String value = (String) this.properties.get(propName);
    if (value == null) {
      return null;
    }
    value = value.trim();
    if (value.equals("")) {
      return null;
    }
    value = resolvePropertyValue(value, msgCtxt);
    if (value == null || value.equals("")) {
      return null;
    }
    return value;
  }

  protected String getSimpleRequiredProperty(String propName, MessageContext msgCtxt)
      throws IllegalStateException {
    String value = (String) this.properties.get(propName);
    if (value == null) {
      throw new IllegalStateException(propName + " resolves to an empty string");
    }
    value = value.trim();
    if (value.equals("")) {
      throw new IllegalStateException(propName + " resolves to an empty string");
    }
    value = resolvePropertyValue(value, msgCtxt);
    if (value == null || value.equals("")) {
      throw new IllegalStateException(propName + " resolves to an empty string");
    }
    return value;
  }

  // If the value of a property contains any pairs of curlies,
  // eg, {apiproxy.name}, then "resolve" the value by de-referencing
  // the context variables whose names appear between curlies.
  private String resolvePropertyValue(String spec, MessageContext msgCtxt) {
    Matcher matcher = variableReferencePattern.matcher(spec);
    StringBuffer sb = new StringBuffer();
    while (matcher.find()) {
      matcher.appendReplacement(sb, "");
      sb.append(matcher.group(1));
      Object v = msgCtxt.getVariable(matcher.group(2));
      if (v != null) {
        sb.append((String) v);
      }
      sb.append(matcher.group(3));
    }
    matcher.appendTail(sb);
    return sb.toString();
  }

  protected X509Certificate getCertificate(MessageContext msgCtxt)
      throws NoSuchAlgorithmException, InvalidNameException, KeyException, CertificateException {
    String certificateString = getSimpleRequiredProperty("certificate", msgCtxt);
    certificateString = certificateString.trim();
    X509Certificate certificate = (X509Certificate) certificateFromPEM(certificateString);
    X500Principal principal = certificate.getIssuerX500Principal();
    msgCtxt.setVariable(varName("cert_issuer_cn"), getCommonName(principal));
    msgCtxt.setVariable(varName("cert_thumbprint"), getThumbprintHex(certificate));
    msgCtxt.setVariable(
        varName("cert_notAfter"),
        DateTimeFormatter.ISO_INSTANT.format(certificate.getNotAfter().toInstant()));
    msgCtxt.setVariable(
        varName("cert_notBefore"),
        DateTimeFormatter.ISO_INSTANT.format(certificate.getNotBefore().toInstant()));
    Date now = new java.util.Date();
    if (certificate.getNotBefore().compareTo(now) > 0)
      throw new CertificateNotYetValidException("Certificate is not yet valid.");

    if (certificate.getNotAfter().compareTo(now) < 0)
      throw new CertificateExpiredException("Certificate is expired.");

    return certificate;
  }

  enum IssuerNameStyle {
    NOT_SPECIFIED,
    SHORT,
    SUBJECT_DN
  }

  protected IssuerNameStyle getIssuerNameStyle(MessageContext msgCtxt) {
    String kitString = getSimpleOptionalProperty("issuer-name-style", msgCtxt);
    if (kitString == null) return IssuerNameStyle.SHORT;
    kitString = kitString.trim().toUpperCase();
    if (kitString.equals("SHORT")) return IssuerNameStyle.SHORT;
    if (kitString.equals("SUBJECT_DN")) return IssuerNameStyle.SUBJECT_DN;
    msgCtxt.setVariable(varName("warning"), "unrecognized issuer-name-style");
    return IssuerNameStyle.SHORT;
  }

  protected static String reformIndents(String s) {
    return s.trim().replaceAll("([\\r|\\n|\\r\\n] *)", "\n");
  }

  protected static Certificate certificateFromPEM(String certificateString) throws KeyException {
    try {
      CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
      certificateString = reformIndents(certificateString);
      Certificate certificate =
          certFactory.generateCertificate(
              new ByteArrayInputStream(certificateString.getBytes(StandardCharsets.UTF_8)));
      return certificate;
    } catch (Exception ex) {
      throw new KeyException("cannot instantiate certificate", ex);
    }
  }

  protected static String getCommonName(X500Principal principal) throws InvalidNameException {
    LdapName ldapDN = new LdapName(principal.getName());
    String cn = null;
    for (Rdn rdn : ldapDN.getRdns()) {
      // System.out.println(rdn.getType() + " -> " + rdn.getValue());
      if (rdn.getType().equals("CN")) {
        cn = rdn.getValue().toString();
      }
    }
    return cn;
  }

  protected static String getThumbprintBase64(X509Certificate certificate)
      throws NoSuchAlgorithmException, CertificateEncodingException {
    return Base64.getEncoder()
        .encodeToString(MessageDigest.getInstance("SHA-1").digest(certificate.getEncoded()));
  }

  protected static String getThumbprintHex(X509Certificate certificate)
      throws NoSuchAlgorithmException, CertificateEncodingException {
    return DatatypeConverter.printHexBinary(
            MessageDigest.getInstance("SHA-1").digest(certificate.getEncoded()))
        .toLowerCase();
  }

  protected static String getStackTraceAsString(Throwable t) {
    StringWriter sw = new StringWriter();
    PrintWriter pw = new PrintWriter(sw);
    t.printStackTrace(pw);
    return sw.toString();
  }

  protected void setExceptionVariables(Exception exc1, MessageContext msgCtxt) {
    String error = exc1.toString().replaceAll("\n", " ");
    msgCtxt.setVariable(varName("exception"), error);
    Matcher matcher = commonErrorPattern.matcher(error);
    if (matcher.matches()) {
      msgCtxt.setVariable(varName("error"), matcher.group(2));
    } else {
      msgCtxt.setVariable(varName("error"), error);
    }
  }
}
