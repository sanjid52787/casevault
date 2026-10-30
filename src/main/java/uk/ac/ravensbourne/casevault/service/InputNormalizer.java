package uk.ac.ravensbourne.casevault.service;
import java.text.Normalizer; import org.springframework.stereotype.Service;
/** Rejects control/NUL input and normalises title compatibility forms before persistence (CWE-20). */
@Service public class InputNormalizer { public String title(String value){return validate(Normalizer.normalize(value,Normalizer.Form.NFKC));} public String text(String value){return validate(value);} private String validate(String v){if(v.indexOf('\0')>=0||v.chars().anyMatch(c->Character.isISOControl(c)&&c!='\n'&&c!='\t'))throw new IllegalArgumentException("Invalid control character");return v;} }
