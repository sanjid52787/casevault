package uk.ac.ravensbourne.casevault.common;

/** Removes CR/LF from user-controlled values before structured logging (CWE-117). */
public final class LogSanitizer { private LogSanitizer(){} public static String value(String input){return input==null?"":input.replace("\r","").replace("\n","");} }
