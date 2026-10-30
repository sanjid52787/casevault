package uk.ac.ravensbourne.casevault.security;
import static org.junit.jupiter.api.Assertions.*; import org.junit.jupiter.api.Test;
class PasswordPolicyTest { private final PasswordPolicy policy=new PasswordPolicy(); @Test void tAuth009RejectsWeakCommonAndEmailPasswords(){assertThrows(IllegalArgumentException.class,()->policy.validate("password123","user@example.test"));assertThrows(IllegalArgumentException.class,()->policy.validate("user@example.test","user@example.test"));assertDoesNotThrow(()->policy.validate("correct horse battery staple","user@example.test"));} }
