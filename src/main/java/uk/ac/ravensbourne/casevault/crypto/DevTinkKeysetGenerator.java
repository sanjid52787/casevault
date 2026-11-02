package uk.ac.ravensbourne.casevault.crypto;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Development-only CLI for generating a Tink AES-256-GCM keyset outside source control.
 * The caller must store the result as a secret and set {@code TINK_KEYSET_PATH}; it never logs key material.
 */
public final class DevTinkKeysetGenerator {
    private DevTinkKeysetGenerator() { }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("Expected one output keyset path");
        Path output = Path.of(args[0]).toAbsolutePath().normalize();
        if (Files.exists(output)) throw new IllegalStateException("Refusing to overwrite an existing keyset");
        Path parent = output.getParent();
        if (parent == null) throw new IllegalArgumentException("Keyset path requires a parent directory");
        Files.createDirectories(parent);
        AeadConfig.register();
        KeysetHandle keyset = KeysetHandle.generateNew(AeadKeyTemplates.AES256_GCM);
        CleartextKeysetHandle.write(keyset, JsonKeysetWriter.withPath(output));
    }
}
