package com.google.apigee.edgecallouts.samlauthn;

public enum BindingType {
  NOT_SPECIFIED,
  HTTP_REDIRECT,
  HTTP_POST;

  static BindingType fromString(String s) {
    for (BindingType t : BindingType.values()) {
      if (t.name().equals(s)) return t;
    }
    return BindingType.NOT_SPECIFIED;
  }
}
