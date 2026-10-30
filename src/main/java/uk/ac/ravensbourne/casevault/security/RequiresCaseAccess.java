package uk.ac.ravensbourne.casevault.security;

import java.lang.annotation.*;
/** Marks a public service operation that must apply the central case access gate (CWE-639). */
@Target(ElementType.METHOD) @Retention(RetentionPolicy.RUNTIME)
public @interface RequiresCaseAccess { }
