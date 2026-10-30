package uk.ac.ravensbourne.casevault.service;
import org.springframework.http.HttpStatus; import org.springframework.web.bind.annotation.ResponseStatus;
/** Uses 404 for unauthorised objects to avoid existence disclosure (CWE-204). */
@ResponseStatus(HttpStatus.NOT_FOUND) public class CaseNotFoundException extends RuntimeException { public CaseNotFoundException(){super("Case not found");} }
