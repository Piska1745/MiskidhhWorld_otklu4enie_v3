package net.miskidhhworld.accountlock;

import java.util.UUID;

public final class LockRecord {
    public final UUID uuid;
    public final String playerName;
    public final String adminName;
    public final String reason;
    public final long createdAt;
    public final byte[] ipHash;

    public LockRecord(UUID uuid, String playerName, String adminName, String reason,
                      long createdAt, byte[] ipHash) {
        this.uuid = uuid;
        this.playerName = playerName;
        this.adminName = adminName;
        this.reason = reason;
        this.createdAt = createdAt;
        this.ipHash = ipHash.clone();
    }
}
