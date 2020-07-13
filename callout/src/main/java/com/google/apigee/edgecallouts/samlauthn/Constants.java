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

public final class Constants {

  public final static String AUTHN_REQUEST_TEMPLATE =
    ""
    + "<samlp:AuthnRequest\n"
    + "    xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol'\n"
    + "    xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'\n"
    + "    Version='2.0'\n"
    + "    ProviderName='@@SERVICE_PROVIDER_NAME@@'\n"
    + "    IssueInstant='@@ISSUE_INSTANT@@'\n"
    + "    Destination='@@DESTINATION@@'\n"
    + "    ProtocolBinding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'\n"
    + "    AssertionConsumerServiceURL='@@ACS_URL@@'>\n"
    + "  <saml:Issuer>@@ISSUER@@</saml:Issuer>\n"
    + "</samlp:AuthnRequest>\n";

  public final static String NAME_ID_PERSISTENT =
    "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

  public final static String NAME_ID_TRANSIENT =
    "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" ;

  public final static String NAME_ID_EMAIL =
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

  public final static String NAME_ID_UNSPECIFIED =
  "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";

  public final static String AUTHN_CONTEXT_CLASS_REF_PASSWORD =
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";

  private Constants() { }

}
