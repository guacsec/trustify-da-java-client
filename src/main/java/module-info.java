module io.github.guacsec.trustifyda {
  requires java.net.http;
  requires com.fasterxml.jackson.annotation;
  requires com.fasterxml.jackson.core;
  requires transitive com.fasterxml.jackson.databind;
  requires jakarta.annotation;
  requires java.xml;
  requires jakarta.mail;
  requires transitive trustifyda.api;
  requires cyclonedx.core.java;
  requires transitive packageurl.java;
  requires transitive java.logging;
  requires org.tomlj;
  requires java.base;

  opens io.github.guacsec.trustifyda.providers to
      com.fasterxml.jackson.databind;

  exports io.github.guacsec.trustifyda;
  exports io.github.guacsec.trustifyda.impl;
  exports io.github.guacsec.trustifyda.sbom;
  exports io.github.guacsec.trustifyda.tools;
  exports io.github.guacsec.trustifyda.utils;

  opens io.github.guacsec.trustifyda.utils to
      com.fasterxml.jackson.databind;
  opens io.github.guacsec.trustifyda.sbom to
      com.fasterxml.jackson.databind,
      packageurl.java;

  exports io.github.guacsec.trustifyda.providers;
  exports io.github.guacsec.trustifyda.providers.javascript.model;
  exports io.github.guacsec.trustifyda.logging;
  exports io.github.guacsec.trustifyda.image;

  opens io.github.guacsec.trustifyda.image to
      com.fasterxml.jackson.databind;
}
