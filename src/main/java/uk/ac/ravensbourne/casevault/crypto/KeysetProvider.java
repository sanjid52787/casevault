package uk.ac.ravensbourne.casevault.crypto; import com.google.crypto.tink.Aead; public interface KeysetProvider { Aead aead() throws Exception; }
