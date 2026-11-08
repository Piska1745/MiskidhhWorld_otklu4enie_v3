package net.miskidhhworld.accountlock;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.plugin.java.JavaPlugin;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;

public final class AccountLockPlugin extends JavaPlugin implements Listener {
    private static final int MAGIC = 0x41434C33; // ACL3
    private static final int VERSION = 3;
    private static final int NONCE_LENGTH = 12;
    private static final int HASH_LENGTH = 32;
    private static final int MAX_RECORDS = 100_000;
    private static final String SERVER_NAME = "MiskidhhWorld";

    private final Map<UUID, LockRecord> records = new HashMap<>();
    private final Map<String, LockRecord> ipIndex = new HashMap<>();
    private SecretKeySpec encryptionKey;
    private SecretKeySpec ipHmacKey;
    private Path dataFile;
    private volatile boolean storageHealthy;

    @Override
    public void onEnable() {
        dataFile = getDataFolder().toPath().resolve("vault.dat");

        try {
            byte[] master = readMasterKey();
            encryptionKey = new SecretKeySpec(master, "AES");
            ipHmacKey = new SecretKeySpec(deriveIpKey(master), "HmacSHA256");
            Files.createDirectories(getDataFolder().toPath());
            loadStore();
            storageHealthy = true;
            getLogger().info("Loaded " + records.size() + " encrypted account lock record(s).");
        } catch (Exception ex) {
            storageHealthy = false;
            getLogger().severe("Encrypted account vault could not be loaded: " + ex.getMessage());
            getLogger().severe("FAIL-CLOSED: login attempts will be rejected until the correct key and vault are restored.");
        }

        Bukkit.getPluginManager().registerEvents(this, this);
    }

    private byte[] readMasterKey() {
        String hex = System.getenv("ACCOUNTLOCK_MASTER_KEY");
        if (hex == null || !hex.matches("(?i)[0-9a-f]{64}")) {
            throw new IllegalStateException("ACCOUNTLOCK_MASTER_KEY must contain exactly 64 hexadecimal characters.");
        }
        return HexFormat.of().parseHex(hex);
    }

    private byte[] deriveIpKey(byte[] master) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(master, "HmacSHA256"));
        return mac.doFinal("MiskidhhWorld/AccountLock/V3/IP-HMAC".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private byte[] hashIp(InetAddress address) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(ipHmacKey);
        return mac.doFinal(address.getAddress());
    }

    private String hashKey(byte[] hash) {
        return HexFormat.of().formatHex(hash);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onPreLogin(AsyncPlayerPreLoginEvent event) {
        if (!storageHealthy) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                    "§c§lMiskidhhWorld\n§4Account verification is unavailable.\n§cPlease contact the server owner.");
            return;
        }

        LockRecord uuidRecord = records.get(event.getUniqueId());
        if (uuidRecord != null) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_BANNED, disabledMessage(uuidRecord));
            return;
        }

        try {
            LockRecord ipRecord = ipIndex.get(hashKey(hashIp(event.getAddress())));
            if (ipRecord != null) {
                event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_BANNED,
                        "§c§lMiskidhhWorld\n§4§lАККАУНТ ОТКЛЮЧЁН\n\n"
                        + "§fДоступ с этого сетевого адреса заблокирован системой безопасности сервера.\n"
                        + "§cВозврат доступа возможен только через систему восстановления.");
            }
        } catch (Exception ex) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                    "§c§lMiskidhhWorld\n§cAccount verification failed. Contact the server owner.");
            getLogger().severe("Could not verify login network fingerprint: " + ex.getMessage());
        }
    }

    private String disabledMessage(LockRecord record) {
        return "§c§lMiskidhhWorld\n\n§4§lАККАУНТ ОТКЛЮЧЁН\n\n"
                + "§fВаш аккаунт был отключён администрацией сервера.\n"
                + "§cВозврат аккаунта невозможен.\n"
                + (record.reason.isBlank() ? "" : "§7Причина: " + record.reason);
    }

    @Override
    public boolean onCommand(org.bukkit.command.CommandSender sender,
                             org.bukkit.command.Command command,
                             String label, String[] args) {
        if (!storageHealthy) {
            sender.sendMessage(ChatColor.RED + "AccountLock vault is unavailable. No changes can be made.");
            return true;
        }

        // Deliberately require a player with an explicit LuckPerms permission.
        // Console and OP status alone do not grant this permission.
        if (!(sender instanceof Player admin)) {
            sender.sendMessage("This command can only be used by a player with accountlock.disable.");
            return true;
        }

        if (args.length >= 3 && args[0].equalsIgnoreCase("disable")) {
            if (!admin.hasPermission("accountlock.disable")) {
                admin.sendMessage(ChatColor.RED + "You do not have permission.");
                return true;
            }

            Player target = Bukkit.getPlayerExact(args[1]);
            if (target == null) {
                admin.sendMessage(ChatColor.RED + "The target must be online so their UUID and current network address can be recorded.");
                return true;
            }
            if (target.getUniqueId().equals(admin.getUniqueId())) {
                admin.sendMessage(ChatColor.RED + "You cannot disable your own account.");
                return true;
            }

            String reason = String.join(" ", Arrays.copyOfRange(args, 2, args.length)).trim();
            if (reason.isBlank()) {
                admin.sendMessage(ChatColor.RED + "A reason is required.");
                return true;
            }

            InetSocketAddress socket = target.getAddress();
            if (socket == null || socket.getAddress() == null) {
                admin.sendMessage(ChatColor.RED + "Could not read the target's network address.");
                return true;
            }

            UUID uuid = target.getUniqueId();
            if (records.containsKey(uuid)) {
                admin.sendMessage(ChatColor.YELLOW + "This UUID is already disabled.");
                return true;
            }

            try {
                byte[] ipHash = hashIp(socket.getAddress());
                LockRecord record = new LockRecord(uuid, target.getName(), admin.getName(),
                        reason, System.currentTimeMillis(), ipHash);

                records.put(uuid, record);
                ipIndex.put(hashKey(ipHash), record);
                try {
                    saveStore();
                } catch (Exception saveError) {
                    records.remove(uuid);
                    ipIndex.remove(hashKey(ipHash));
                    throw saveError;
                }

                String announcement = ChatColor.RED + "[MiskidhhWorld] "
                        + ChatColor.YELLOW + "Аккаунт игрока " + ChatColor.WHITE + target.getName()
                        + ChatColor.YELLOW + " был отключён администратором " + ChatColor.WHITE
                        + admin.getName() + ChatColor.YELLOW + " по причине: " + ChatColor.WHITE + reason
                        + ChatColor.GRAY + ". Возврат аккаунта — только через систему восстановления.";

                Bukkit.broadcastMessage(announcement);
                target.kickPlayer(disabledMessage(record));
                admin.sendMessage(ChatColor.GREEN + "Account disabled and encrypted record saved.");
            } catch (Exception ex) {
                admin.sendMessage(ChatColor.RED + "Could not save the encrypted lock. No lock was applied.");
                getLogger().severe("Failed to save lock record: " + ex.getMessage());
            }
            return true;
        }

        if (args.length == 2 && args[0].equalsIgnoreCase("status")) {
            if (!admin.hasPermission("accountlock.audit")) {
                admin.sendMessage(ChatColor.RED + "You do not have permission.");
                return true;
            }
            Player target = Bukkit.getPlayerExact(args[1]);
            if (target == null) {
                admin.sendMessage(ChatColor.RED + "Player must be online.");
                return true;
            }
            LockRecord record = records.get(target.getUniqueId());
            admin.sendMessage(record == null
                    ? ChatColor.GREEN + "UUID is not disabled."
                    : ChatColor.RED + "UUID is disabled. Reason: " + record.reason);
            return true;
        }

        sender.sendMessage(ChatColor.YELLOW + "Usage: /accountlock disable <online-player> <reason>");
        sender.sendMessage(ChatColor.YELLOW + "       /accountlock status <online-player>");
        return true;
    }

    private void loadStore() throws Exception {
        records.clear();
        ipIndex.clear();
        if (!Files.exists(dataFile)) return;

        byte[] file = Files.readAllBytes(dataFile);
        if (file.length < NONCE_LENGTH + 16) throw new IOException("Vault is truncated.");

        byte[] nonce = Arrays.copyOfRange(file, 0, NONCE_LENGTH);
        byte[] encrypted = Arrays.copyOfRange(file, NONCE_LENGTH, file.length);
        byte[] plain = crypt(Cipher.DECRYPT_MODE, nonce, encrypted);

        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(plain))) {
            if (in.readInt() != MAGIC || in.readInt() != VERSION) {
                throw new IOException("Wrong vault format or version.");
            }
            int count = in.readInt();
            if (count < 0 || count > MAX_RECORDS) throw new IOException("Invalid record count.");

            for (int i = 0; i < count; i++) {
                UUID uuid = new UUID(in.readLong(), in.readLong());
                String playerName = in.readUTF();
                String adminName = in.readUTF();
                String reason = in.readUTF();
                long createdAt = in.readLong();
                int hashLength = in.readInt();
                if (hashLength != HASH_LENGTH) throw new IOException("Invalid IP fingerprint.");
                byte[] ipHash = in.readNBytes(hashLength);
                if (ipHash.length != hashLength) throw new EOFException("Truncated IP fingerprint.");

                LockRecord record = new LockRecord(uuid, playerName, adminName, reason, createdAt, ipHash);
                records.put(uuid, record);
                ipIndex.put(hashKey(ipHash), record);
            }
            if (in.available() != 0) throw new IOException("Unexpected trailing vault data.");
        }
    }

    private void saveStore() throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bytes)) {
            out.writeInt(MAGIC);
            out.writeInt(VERSION);
            out.writeInt(records.size());
            for (LockRecord r : records.values()) {
                out.writeLong(r.uuid.getMostSignificantBits());
                out.writeLong(r.uuid.getLeastSignificantBits());
                out.writeUTF(r.playerName);
                out.writeUTF(r.adminName);
                out.writeUTF(r.reason);
                out.writeLong(r.createdAt);
                out.writeInt(r.ipHash.length);
                out.write(r.ipHash);
            }
        }

        byte[] nonce = new byte[NONCE_LENGTH];
        new SecureRandom().nextBytes(nonce);
        byte[] ciphertext = crypt(Cipher.ENCRYPT_MODE, nonce, bytes.toByteArray());

        Path temp = dataFile.resolveSibling("vault.dat.tmp");
        try (OutputStream out = Files.newOutputStream(temp, StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
            out.write(nonce);
            out.write(ciphertext);
        }
        try {
            Files.move(temp, dataFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException ex) {
            Files.move(temp, dataFile, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private byte[] crypt(int mode, byte[] nonce, byte[] input) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, encryptionKey, new GCMParameterSpec(128, nonce));
        cipher.updateAAD(new byte[]{'A', 'C', 'L', '3', (byte) VERSION});
        return cipher.doFinal(input);
    }
}
