import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.*;
import java.util.*;

/*
 * Owner-only offline recovery utility.
 * It is intentionally separate from the server plugin: there is no in-game
 * unban/restore command. Keep the compiled tool and master key private.
 */
public final class RecoveryTool {
    private static final int MAGIC = 0x41434C33;
    private static final int VERSION = 3;
    private static final int NONCE_LENGTH = 12;
    private static final int HASH_LENGTH = 32;

    private record Entry(UUID uuid, String player, String admin, String reason,
                         long createdAt, byte[] ipHash) {}

    public static void main(String[] args) throws Exception {
        if (args.length < 2 || args.length > 3
                || !(args[0].equals("list") || args[0].equals("restore"))
                || (args[0].equals("list") && args.length != 2)
                || (args[0].equals("restore") && args.length != 3)) {
            System.out.println("Usage:");
            System.out.println("  java RecoveryTool list <path-to-vault.dat>");
            System.out.println("  java RecoveryTool restore <path-to-vault.dat> <UUID>");
            return;
        }

        String action = args[0];
        Path file = Path.of(args[1]);
        List<Entry> entries = read(file);
        if (action.equals("list")) {
            for (Entry e : entries) {
                System.out.println(e.uuid() + " | " + e.player() + " | by " + e.admin()
                        + " | " + e.reason() + " | " + new Date(e.createdAt()));
            }
            System.out.println("Total records: " + entries.size());
            return;
        }

        UUID target = UUID.fromString(args[2]);
        boolean removed = entries.removeIf(e -> e.uuid().equals(target));
        if (!removed) {
            System.out.println("No record found for " + target);
            return;
        }
        write(file, entries);
        System.out.println("Restored UUID " + target + ". Make sure you intended to remove this lock.");
    }

    private static byte[] key() {
        String hex = System.getenv("ACCOUNTLOCK_MASTER_KEY");
        if (hex == null || !hex.matches("(?i)[0-9a-f]{64}")) {
            throw new IllegalStateException("Set ACCOUNTLOCK_MASTER_KEY to the same 64-hex-character master key.");
        }
        return HexFormat.of().parseHex(hex);
    }

    private static void write(Path file, List<Entry> entries) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bytes)) {
            out.writeInt(MAGIC);
            out.writeInt(VERSION);
            out.writeInt(entries.size());
            for (Entry e : entries) {
                out.writeLong(e.uuid().getMostSignificantBits());
                out.writeLong(e.uuid().getLeastSignificantBits());
                out.writeUTF(e.player());
                out.writeUTF(e.admin());
                out.writeUTF(e.reason());
                out.writeLong(e.createdAt());
                out.writeInt(e.ipHash().length);
                out.write(e.ipHash());
            }
        }

        byte[] nonce = new byte[NONCE_LENGTH];
        new java.security.SecureRandom().nextBytes(nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key(), "AES"),
                new GCMParameterSpec(128, nonce));
        cipher.updateAAD(new byte[]{'A', 'C', 'L', '3', (byte) VERSION});
        byte[] encrypted = cipher.doFinal(bytes.toByteArray());

        Path temp = file.resolveSibling(file.getFileName() + ".tmp");
        try (OutputStream out = Files.newOutputStream(temp)) {
            out.write(nonce);
            out.write(encrypted);
        }
        try {
            Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException ex) {
            Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static List<Entry> read(Path file) throws Exception {
        byte[] all = Files.readAllBytes(file);
        if (all.length < NONCE_LENGTH + 16) throw new IOException("Vault is truncated.");
        byte[] nonce = Arrays.copyOfRange(all, 0, NONCE_LENGTH);
        byte[] encrypted = Arrays.copyOfRange(all, NONCE_LENGTH, all.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key(), "AES"),
                new GCMParameterSpec(128, nonce));
        cipher.updateAAD(new byte[]{'A', 'C', 'L', '3', (byte) VERSION});
        byte[] plain = cipher.doFinal(encrypted);

        List<Entry> entries = new ArrayList<>();
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(plain))) {
            if (in.readInt() != MAGIC || in.readInt() != VERSION) throw new IOException("Wrong vault format.");
            int count = in.readInt();
            if (count < 0 || count > 100_000) throw new IOException("Invalid record count.");
            for (int i = 0; i < count; i++) {
                UUID uuid = new UUID(in.readLong(), in.readLong());
                String player = in.readUTF();
                String admin = in.readUTF();
                String reason = in.readUTF();
                long createdAt = in.readLong();
                int hashLength = in.readInt();
                if (hashLength != HASH_LENGTH) throw new IOException("Invalid IP fingerprint.");
                byte[] hash = in.readNBytes(hashLength);
                if (hash.length != hashLength) throw new EOFException();
                entries.add(new Entry(uuid, player, admin, reason, createdAt, hash));
            }
        }
        return entries;
    }
}
